// Package websnapshot is the built-in capability that acquires website
// evidence. It performs passive requests only: a GET of the front page and
// a GET of its plain-http variant to observe the HTTPS redirect.
package websnapshot

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"regexp"

	"golang.org/x/net/html"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/webtext"
)

//go:embed capability.yaml
var capabilityYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

// MaxBody is the maximum number of body bytes kept.
const MaxBody = 2 << 20

// MaxPages is how many additional same-site pages are read.
const MaxPages = 5

// maxPageBytes caps each additional page.
const maxPageBytes = 512 << 10

// Analyzer implements the web-snapshot capability.
type Analyzer struct{}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

// Analyze implements analyzer.Analyzer.
func (*Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	if in.HTTP == nil {
		return nil, errors.New("no network client available")
	}
	start := in.Now()
	snap := &facts.WebSnapshot{RequestedURL: in.Target.URL, FetchedAt: start.UTC()}

	client := *in.HTTP
	var chain []string
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		chain = append(chain, req.URL.String())
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.Target.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		// An invalid certificate is itself important evidence: publish it
		// so web-security can report it, instead of failing the scan.
		snap.FinalURL = in.Target.URL
		snap.TLS = &facts.TLSInfo{VerifyError: certErr.Err.Error()}
		if len(certErr.UnverifiedCertificates) > 0 {
			leaf := certErr.UnverifiedCertificates[0]
			snap.TLS.Subject, snap.TLS.Issuer, snap.TLS.NotAfter, snap.TLS.DNSNames = leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotAfter.UTC(), leaf.DNSNames
		}
		snap.DurationMS = in.Now().Sub(start).Milliseconds()
		return &analyzer.Result{
			Evidence:    map[string]any{facts.KeyWebSnapshot: snap},
			Summary:     "TLS certificate verification failed; the page was not fetched.",
			Limitations: []string{"The page content could not be fetched securely, so content-based checks were not possible."},
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", in.Target.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", in.Target.URL, err)
	}
	if len(body) > MaxBody {
		body, snap.Truncated = body[:MaxBody], true
	}
	snap.FinalURL = resp.Request.URL.String()
	snap.Status = resp.StatusCode
	snap.Headers = resp.Header
	snap.Redirects = chain
	snap.BodyBytes = len(body)
	snap.ContentType = resp.Header.Get("Content-Type")
	snap.DurationMS = in.Now().Sub(start).Milliseconds()
	if resp.TLS != nil {
		snap.TLS = tlsInfo(resp.TLS, resp.Request.URL.Hostname())
	}
	for _, c := range resp.Cookies() {
		ss := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			ss = "Lax"
		case http.SameSiteStrictMode:
			ss = "Strict"
		case http.SameSiteNoneMode:
			ss = "None"
		}
		snap.Cookies = append(snap.Cookies, facts.Cookie{Name: c.Name, Secure: c.Secure, HTTPOnly: c.HttpOnly, SameSite: ss, Domain: c.Domain})
	}
	if isHTML(snap.ContentType, body) {
		snap.Body = string(body)
		parsePage(snap, body, resp.Request.URL)
	}

	var limits []string
	if u, err := url.Parse(snap.FinalURL); err == nil && u.Scheme == "https" {
		up, err := httpsUpgrade(ctx, in.HTTP, u)
		if err != nil {
			limits = append(limits, "Could not check whether plain HTTP redirects to HTTPS: "+err.Error())
		} else {
			snap.HTTPSUpgrade = &up
		}
	}
	if snap.Truncated {
		limits = append(limits, fmt.Sprintf("Page body larger than %d bytes was truncated.", MaxBody))
	}
	if final, err := url.Parse(snap.FinalURL); err == nil && snap.Status == 200 && len(snap.Links) > 0 {
		snap.Pages = crawl(ctx, in.HTTP, final, snap.Links, MaxPages)
	}
	limits = append(limits, fmt.Sprintf("The front page and up to %d linked pages of the same site were read (%d this time); authenticated areas and the rest of the site were not inspected.", MaxPages, len(snap.Pages)))
	return &analyzer.Result{
		Evidence:    map[string]any{facts.KeyWebSnapshot: snap},
		Summary:     fmt.Sprintf("HTTP %d from %s in %dms (%d bytes); %d more page(s) read", snap.Status, snap.FinalURL, snap.DurationMS, snap.BodyBytes, len(snap.Pages)),
		Limitations: limits,
	}, nil
}

func isHTML(contentType string, body []byte) bool {
	mt, _, _ := mime.ParseMediaType(contentType)
	if mt == "text/html" || mt == "application/xhtml+xml" {
		return true
	}
	head := bytes.ToLower(body[:min(len(body), 512)])
	return bytes.Contains(head, []byte("<html")) || bytes.Contains(head, []byte("<!doctype html"))
}

func httpsUpgrade(ctx context.Context, base *http.Client, u *url.URL) (bool, error) {
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	plain := &url.URL{Scheme: "http", Host: u.Host, Path: "/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, plain.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	return resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(strings.ToLower(loc), "https://"), nil
}

func tlsInfo(cs *tls.ConnectionState, host string) *facts.TLSInfo {
	ti := &facts.TLSInfo{Version: tls.VersionName(cs.Version), CipherSuite: tls.CipherSuiteName(cs.CipherSuite)}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		ti.Issuer = leaf.Issuer.CommonName
		if len(leaf.Issuer.Organization) > 0 {
			ti.Issuer = leaf.Issuer.Organization[0]
		}
		ti.Subject = leaf.Subject.CommonName
		ti.DNSNames = leaf.DNSNames
		ti.NotAfter = leaf.NotAfter.UTC()
		pool := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			pool.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: pool, CurrentTime: time.Now()}); err != nil {
			ti.VerifyError = err.Error()
		}
	}
	return ti
}

// parsePage extracts title, meta tags and referenced resources.
func parsePage(s *facts.WebSnapshot, body []byte, base *url.URL) {
	s.Meta = map[string]string{}
	z := html.NewTokenizer(bytes.NewReader(body))
	inTitle := false
	seen := map[string]bool{}
	addRes := func(kind, ref string, sri bool) {
		if ref == "" || strings.HasPrefix(ref, "data:") {
			return
		}
		u, err := base.Parse(ref)
		if err != nil {
			return
		}
		key := kind + " " + u.String()
		if seen[key] || len(s.Resources) >= 500 {
			return
		}
		seen[key] = true
		s.Resources = append(s.Resources, facts.Resource{Kind: kind, URL: u.String(), SRI: sri})
	}
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return
		case html.TextToken:
			if inTitle && s.Title == "" {
				s.Title = strings.TrimSpace(string(z.Text()))
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "title" {
				inTitle = false
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			switch string(name) {
			case "title":
				inTitle = true
			case "meta":
				key := strings.ToLower(attrs["name"])
				if key == "" {
					key = strings.ToLower(attrs["property"])
				}
				if key == "" {
					key = strings.ToLower(attrs["http-equiv"])
				}
				if key != "" && attrs["content"] != "" && len(s.Meta) < 100 {
					s.Meta[key] = attrs["content"]
				}
			case "script":
				addRes("script", attrs["src"], attrs["integrity"] != "")
			case "link":
				rel := strings.ToLower(attrs["rel"])
				kind := "link"
				if strings.Contains(rel, "stylesheet") {
					kind = "stylesheet"
				}
				addRes(kind, attrs["href"], attrs["integrity"] != "")
			case "a":
				addLink(s, attrs["href"], base)
			case "iframe":
				addRes("iframe", attrs["src"], false)
			case "img":
				if len(s.Resources) < 200 {
					addRes("img", attrs["src"], false)
				}
			}
		}
	}
}

// skipLink excludes links that are not content pages or that could trigger
// an action even over GET (logout, cart, delete...).
var skipLink = regexp.MustCompile(`(?i)(logout|log-out|signout|sign-out|/cart|add-to-cart|/checkout|delete|unsubscribe|/wp-admin|/admin|login|/signin|/register|/feed|\.(pdf|zip|gz|jpe?g|png|gif|webp|svg|mp4|mp3|css|js|json|xml|ico|woff2?)$)`)

// addLink records a same-host page link (fragment removed, deduplicated).
func addLink(s *facts.WebSnapshot, href string, base *url.URL) {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") || strings.HasPrefix(href, "javascript:") {
		return
	}
	u, err := base.Parse(href)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Hostname(), base.Hostname()) {
		return
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	// Check path and query: "/wp-login.php?action=logout" must be skipped too.
	if skipLink.MatchString(u.Path) || skipLink.MatchString(u.RawQuery) || u.Path == base.Path && u.RawQuery == base.RawQuery {
		return
	}
	v := u.String()
	for _, l := range s.Links {
		if l == v {
			return
		}
	}
	if len(s.Links) < 200 {
		s.Links = append(s.Links, v)
	}
}

// crawl politely reads up to max linked pages: sequentially, same host,
// honouring robots.txt, HTML only.
func crawl(ctx context.Context, c *http.Client, base *url.URL, links []string, max int) []facts.WebPage {
	rules := robots(ctx, c, base)
	var pages []facts.WebPage
	seenPath := map[string]bool{base.Path: true}
	for _, l := range links {
		if len(pages) >= max || ctx.Err() != nil {
			break
		}
		u, err := url.Parse(l)
		if err != nil || seenPath[u.Path] || !rules.allowed(u.Path) {
			continue
		}
		seenPath[u.Path] = true
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9")
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes))
		resp.Body.Close()
		if resp.StatusCode != 200 || !isHTML(resp.Header.Get("Content-Type"), body) {
			continue
		}
		p := facts.WebPage{URL: resp.Request.URL.String(), Status: resp.StatusCode, HTML: string(body)}
		var tmp facts.WebSnapshot
		parsePage(&tmp, body, resp.Request.URL)
		p.Title, p.Generator = tmp.Title, tmp.Meta["generator"]
		p.Text = webtext.Visible(p.HTML)
		p.Words = webtext.Words(p.Text)
		pages = append(pages, p)
		time.Sleep(150 * time.Millisecond) // be gentle with small sites
	}
	return pages
}

type robotsRules struct{ disallow, allow []string }

func (r robotsRules) allowed(p string) bool {
	best, ok := -1, true
	for _, a := range r.allow {
		if strings.HasPrefix(p, a) && len(a) > best {
			best, ok = len(a), true
		}
	}
	for _, d := range r.disallow {
		if d != "" && strings.HasPrefix(p, d) && len(d) > best {
			best, ok = len(d), false
		}
	}
	return ok
}

// robots reads the "User-agent: *" group of robots.txt (prefix rules).
func robots(ctx context.Context, c *http.Client, base *url.URL) robotsRules {
	var r robotsRules
	u := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/robots.txt"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return r
	}
	resp, err := c.Do(req)
	if err != nil {
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return r
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	applies := false
	inAgents := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "user-agent":
			if !inAgents {
				applies = false
			}
			inAgents = true
			if v == "*" || strings.Contains(strings.ToLower(v), "capybari") {
				applies = true
			}
		case "disallow":
			inAgents = false
			if applies {
				r.disallow = append(r.disallow, v)
			}
		case "allow":
			inAgents = false
			if applies {
				r.allow = append(r.allow, v)
			}
		default:
			inAgents = false
		}
	}
	return r
}
