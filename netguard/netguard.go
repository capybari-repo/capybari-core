// Package netguard builds HTTP clients that enforce a capability's declared
// host allow-list, optionally refuse private networks (hosted mode, SSRF
// protection) and record every outbound request for the report's data
// boundary section (Master Plan, Section 12: Privacy & Trust Model).
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrHostNotAllowed is returned when a capability contacts an undeclared host.
var ErrHostNotAllowed = errors.New("host not in capability network allow-list")

// ErrPrivateAddress is returned when private-network access is denied.
var ErrPrivateAddress = errors.New("refusing to connect to a private or local network address")

// Call is one recorded outbound destination.
type Call struct {
	Capability string `json:"capability"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Count      int    `json:"count"`
	Blocked    int    `json:"blocked,omitempty"`
}

// Recorder collects outbound calls across all capabilities of a scan.
type Recorder struct {
	mu    sync.Mutex
	calls map[string]*Call
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder { return &Recorder{calls: map[string]*Call{}} }

func (r *Recorder) add(capability, host, method string, blocked bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := capability + "\x00" + host + "\x00" + method
	c := r.calls[k]
	if c == nil {
		c = &Call{Capability: capability, Host: host, Method: method}
		r.calls[k] = c
	}
	if blocked {
		c.Blocked++
	} else {
		c.Count++
	}
}

// Calls returns recorded calls sorted by capability and host.
func (r *Recorder) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Call, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Capability != out[j].Capability {
			return out[i].Capability < out[j].Capability
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// Policy configures a guarded client.
type Policy struct {
	Capability   string
	AllowedHosts []string // exact hosts or "*.example.com" suffix patterns
	DenyPrivate  bool
	Timeout      time.Duration
	MaxRedirects int
	UserAgent    string
	Recorder     *Recorder
}

// HostAllowed reports whether host matches the allow-list.
func HostAllowed(allowed []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allowed {
		a = strings.ToLower(a)
		if a == host || a == "*" { // "*": any public host (still recorded; private networks still denied in hosted mode)
			return true
		}
		if strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:]) {
			return true
		}
	}
	return false
}

// NewClient returns an http.Client enforcing the policy.
func NewClient(p Policy) *http.Client {
	if p.Timeout == 0 {
		p.Timeout = 20 * time.Second
	}
	if p.MaxRedirects == 0 {
		p.MaxRedirects = 10
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if p.DenyPrivate {
		dialer.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || IsPrivate(ip) {
				return fmt.Errorf("%w: %s", ErrPrivateAddress, host)
			}
			return nil
		}
	}
	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	if p.DenyPrivate {
		// A proxy would bypass the dial-time address check.
		base.Proxy = nil
	}
	return &http.Client{
		Timeout:   p.Timeout,
		Transport: &guard{p: p, next: base},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= p.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", p.MaxRedirects)
			}
			return nil
		},
	}
}

type guard struct {
	p    Policy
	next http.RoundTripper
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", req.URL.Scheme)
	}
	if !HostAllowed(g.p.AllowedHosts, host) {
		if g.p.Recorder != nil {
			g.p.Recorder.add(g.p.Capability, host, req.Method, true)
		}
		return nil, fmt.Errorf("%w: %s (capability %s)", ErrHostNotAllowed, host, g.p.Capability)
	}
	if g.p.DenyPrivate {
		if ip := net.ParseIP(host); ip != nil && IsPrivate(ip) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateAddress, host)
		}
		if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
			return nil, fmt.Errorf("%w: %s", ErrPrivateAddress, host)
		}
	}
	if g.p.Recorder != nil {
		g.p.Recorder.add(g.p.Capability, host, req.Method, false)
	}
	if g.p.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", g.p.UserAgent)
	}
	return g.next.RoundTrip(req)
}

var privateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// IsPrivate reports whether ip is loopback, private, link-local, multicast
// or otherwise not publicly routable.
func IsPrivate(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return slices.ContainsFunc(privateNets, func(n *net.IPNet) bool { return n.Contains(ip) })
}

// ResolvePublic resolves host and fails when any address is private. Used by
// hosted mode to validate user-supplied URLs before a scan starts.
func ResolvePublic(ctx context.Context, host string) error {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if IsPrivate(ip.IP) {
			return fmt.Errorf("%w: %s resolves to %s", ErrPrivateAddress, host, ip.IP)
		}
	}
	return nil
}
