// Package render loads a web page in headless Chromium so that pages built
// by JavaScript (React, Next.js, Vue, site builders) can be read the way a
// visitor sees them.
//
// Chromium is given no network of its own: its DNS and proxy point nowhere,
// and every request the page makes is intercepted over the DevTools protocol
// and performed by the caller's http.Client. The engine's network guard
// therefore still records every host, blocks private networks in hosted
// mode and applies timeouts. Images, fonts and media are not fetched.
//
// The DevTools protocol is spoken over a pipe (--remote-debugging-pipe), so
// no port is opened and no third-party library is needed.
package render

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options bound a render.
type Options struct {
	// Timeout for the whole render (default 20s).
	Timeout time.Duration
	// Settle is how long the network must be quiet after load (default 800ms).
	Settle time.Duration
	// MaxRequests caps requests the page may make (default 250).
	MaxRequests int
	// MaxBytes caps the total bytes fetched for the page (default 25 MiB).
	MaxBytes int64
	// NoSandbox disables Chromium's own sandbox (needed when running as root
	// or where unprivileged user namespaces are unavailable).
	NoSandbox bool
}

// Result is a rendered page.
type Result struct {
	URL      string // final URL after client-side navigation
	HTML     string // serialised DOM after rendering
	Requests int    // requests performed on the page's behalf
	Blocked  int    // requests refused (limits, blocked types, network guard)
	Duration time.Duration
}

// ErrNoBrowser means no Chromium binary was found.
var ErrNoBrowser = errors.New("no headless Chromium found (set CAPYBARI_CHROME or install chrome-headless-shell)")

// Find locates a Chromium binary: $CAPYBARI_CHROME, well-known install
// locations, then $PATH. It returns "" when rendering is unavailable or
// disabled with CAPYBARI_RENDER=0.
func Find() string {
	if os.Getenv("CAPYBARI_RENDER") == "0" {
		return ""
	}
	if p := os.Getenv("CAPYBARI_CHROME"); p != "" {
		if isExec(p) {
			return p
		}
		return ""
	}
	candidates := []string{
		"/opt/capybari-scan/chrome/chrome-headless-shell",
		"/opt/capybari/chrome/chrome-headless-shell",
	}
	if home, err := os.UserHomeDir(); err == nil {
		matches, _ := filepath.Glob(filepath.Join(home, ".cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"))
		for i := len(matches) - 1; i >= 0; i-- {
			candidates = append(candidates, matches[i])
		}
	}
	for _, c := range candidates {
		if isExec(c) {
			return c
		}
	}
	for _, name := range []string{"chrome-headless-shell", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func isExec(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// Page renders one URL with the given Chromium binary, performing every
// request through client.
func Page(ctx context.Context, chrome string, client *http.Client, pageURL string, o Options) (*Result, error) {
	if chrome == "" {
		return nil, ErrNoBrowser
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Settle <= 0 {
		o.Settle = 800 * time.Millisecond
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = 250
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 25 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	start := time.Now()

	profile, err := os.MkdirTemp("", "capybari-render-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(profile)

	args := []string{
		"--headless", "--remote-debugging-pipe", "--user-data-dir=" + profile,
		"--no-first-run", "--no-default-browser-check", "--disable-gpu", "--disable-dev-shm-usage",
		"--disable-extensions", "--disable-background-networking", "--disable-sync", "--disable-default-apps",
		"--disable-component-update", "--disable-breakpad", "--metrics-recording-only", "--mute-audio",
		"--hide-scrollbars", "--window-size=1280,900", "--blink-settings=imagesEnabled=false",
		// No network of its own: every request is intercepted and served by us.
		"--proxy-server=127.0.0.1:9", "--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND",
		"--disable-features=DnsOverHttps,NetworkPrediction,Translate,OptimizationHints",
	}
	if o.NoSandbox {
		args = append(args, "--no-sandbox")
	}
	args = append(args, "about:blank")

	toChrome, chromeIn, err := os.Pipe() // chrome reads fd 3
	if err != nil {
		return nil, err
	}
	chromeOut, fromChrome, err := os.Pipe() // chrome writes fd 4
	if err != nil {
		toChrome.Close()
		chromeIn.Close()
		return nil, err
	}
	cmd := exec.CommandContext(ctx, chrome, args...)
	cmd.ExtraFiles = []*os.File{toChrome, fromChrome}
	cmd.Env = append(os.Environ(), "HOME="+profile)
	var stderr bytes.Buffer
	cmd.Stderr = &limited{w: &stderr, n: 16 << 10}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start chromium: %w", err)
	}
	toChrome.Close()
	fromChrome.Close()
	defer func() {
		chromeIn.Close()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
		chromeOut.Close()
	}()

	c := newConn(chromeIn, chromeOut)
	go c.readLoop()

	res := &Result{URL: pageURL}
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := c.call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &target); err != nil {
		return nil, fmt.Errorf("chromium did not start: %w (%s)", err, firstLine(stderr.String()))
	}
	var attach struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}, &attach); err != nil {
		return nil, err
	}
	sid := attach.SessionID

	var inflight, requests, blocked atomic.Int64
	var bytesUsed atomic.Int64
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	loaded := make(chan struct{}, 1)

	// Serve intercepted requests through the caller's client, without
	// following redirects (the browser follows them, intercepted again).
	fetcher := *client
	fetcher.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	c.onEvent = func(ev event) {
		if ev.SessionID != sid {
			return
		}
		switch ev.Method {
		case "Page.loadEventFired":
			select {
			case loaded <- struct{}{}:
			default:
			}
		case "Fetch.requestPaused":
			var p pausedRequest
			if json.Unmarshal(ev.Params, &p) != nil {
				return
			}
			inflight.Add(1)
			lastActivity.Store(time.Now().UnixNano())
			go func() {
				defer func() {
					inflight.Add(-1)
					lastActivity.Store(time.Now().UnixNano())
				}()
				if !wanted(p.ResourceType) || IsTracker(p.Request.URL) || requests.Load() >= int64(o.MaxRequests) || bytesUsed.Load() >= o.MaxBytes {
					blocked.Add(1)
					c.send("Fetch.failRequest", sid, map[string]any{"requestId": p.RequestID, "errorReason": "BlockedByClient"})
					return
				}
				requests.Add(1)
				status, headers, body, err := serve(ctx, &fetcher, p, o.MaxBytes-bytesUsed.Load())
				if err != nil {
					blocked.Add(1)
					c.send("Fetch.failRequest", sid, map[string]any{"requestId": p.RequestID, "errorReason": "Failed"})
					return
				}
				bytesUsed.Add(int64(len(body)))
				c.send("Fetch.fulfillRequest", sid, map[string]any{
					"requestId": p.RequestID, "responseCode": status, "responseHeaders": headers,
					"body": base64.StdEncoding.EncodeToString(body),
				})
			}()
		}
	}

	for _, step := range []struct {
		method string
		params map[string]any
	}{
		{"Fetch.enable", map[string]any{"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}}},
		{"Page.enable", nil},
		{"Page.navigate", map[string]any{"url": pageURL}},
	} {
		if err := c.call(ctx, sid, step.method, step.params, nil); err != nil {
			return nil, fmt.Errorf("%s: %w", step.method, err)
		}
	}

	// Wait for load, then for the network to settle (single-page apps keep
	// fetching data after the load event).
	select {
	case <-loaded:
	case <-ctx.Done():
	}
	for ctx.Err() == nil {
		quiet := time.Since(time.Unix(0, lastActivity.Load()))
		if inflight.Load() == 0 && quiet >= o.Settle {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Leave a moment even when the overall budget ran out: whatever has
	// rendered so far is still worth reading.
	grab, grabCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer grabCancel()
	var ev struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	expr := `JSON.stringify({u: location.href, h: document.documentElement ? document.documentElement.outerHTML : ""})`
	if err := c.call(grab, sid, "Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true}, &ev); err != nil {
		return nil, fmt.Errorf("read rendered page: %w", err)
	}
	var out struct {
		U string `json:"u"`
		H string `json:"h"`
	}
	if err := json.Unmarshal([]byte(ev.Result.Value), &out); err != nil {
		return nil, err
	}
	if out.U != "" && !strings.HasPrefix(out.U, "chrome-error:") {
		res.URL = out.U
	}
	res.HTML, res.Requests, res.Blocked, res.Duration = out.H, int(requests.Load()), int(blocked.Load()), time.Since(start)
	_ = c.call(grab, "", "Browser.close", nil, nil)
	return res, nil
}

type pausedRequest struct {
	RequestID string `json:"requestId"`
	Request   struct {
		URL      string            `json:"url"`
		Method   string            `json:"method"`
		Headers  map[string]string `json:"headers"`
		PostData string            `json:"postData"`
	} `json:"request"`
	ResourceType string `json:"resourceType"`
}

// wanted reports whether a resource type is needed to read the page.
func wanted(resourceType string) bool {
	switch resourceType {
	case "Image", "Media", "Font", "Ping", "CSPViolationReport", "Manifest", "Prefetch", "SignedExchange", "WebSocket", "EventSource":
		return false
	}
	return true
}

// trackerHosts are analytics, advertising and session-recording services.
// They are never needed to read a page, so rendering blocks them: the scan
// does not count as a visit in the owner's analytics and contacts fewer
// third parties.
var trackerHosts = []string{
	"google-analytics.com", "analytics.google.com", "googletagmanager.com", "googleadservices.com", "doubleclick.net",
	"googlesyndication.com", "clarity.ms", "hotjar.com", "hotjar.io", "segment.com", "segment.io", "mixpanel.com",
	"amplitude.com", "heap.io", "heapanalytics.com", "fullstory.com", "posthog.com", "plausible.io", "matomo.cloud",
	"connect.facebook.net", "facebook.com", "snap.licdn.com", "ads-twitter.com", "analytics.tiktok.com",
	"bat.bing.com", "px.ads.linkedin.com", "stats.wp.com", "cloudflareinsights.com", "newrelic.com", "nr-data.net",
	"browser-intake-datadoghq.com", "sentry.io", "logrocket.io", "mouseflow.com", "crazyegg.com", "quantserve.com",
}

// IsTracker reports whether a URL belongs to a known analytics or tracking host.
func IsTracker(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, t := range trackerHosts {
		if h == t || strings.HasSuffix(h, "."+t) {
			return true
		}
	}
	return false
}

var hopHeaders = map[string]bool{
	"accept-encoding": true, "connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "upgrade": true, "host": true, "content-length": true,
}

// serve performs one intercepted request with the guarded client.
func serve(ctx context.Context, c *http.Client, p pausedRequest, budget int64) (int, []map[string]string, []byte, error) {
	if !strings.HasPrefix(p.Request.URL, "http://") && !strings.HasPrefix(p.Request.URL, "https://") {
		return 0, nil, nil, errors.New("unsupported scheme")
	}
	var body io.Reader
	if p.Request.PostData != "" {
		body = strings.NewReader(p.Request.PostData)
	}
	req, err := http.NewRequestWithContext(ctx, p.Request.Method, p.Request.URL, body)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range p.Request.Headers {
		if !hopHeaders[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	limit := min(budget, 8<<20)
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return 0, nil, nil, err
	}
	var headers []map[string]string
	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		// Go already decoded the body; length and encoding no longer apply.
		if lk == "content-encoding" || lk == "content-length" || lk == "transfer-encoding" {
			continue
		}
		for _, v := range vs {
			headers = append(headers, map[string]string{"name": k, "value": v})
		}
	}
	return resp.StatusCode, headers, data, nil
}

// ---- minimal DevTools protocol client over the pipe ----

type event struct {
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
	SessionID string          `json:"sessionId"`
}

type message struct {
	ID        int64           `json:"id"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
	SessionID string          `json:"sessionId"`
	Result    json.RawMessage `json:"result"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type conn struct {
	w       io.Writer
	r       *bufio.Reader
	wmu     sync.Mutex
	nextID  atomic.Int64
	mu      sync.Mutex
	waiting map[int64]chan message
	onEvent func(event)
	closed  chan struct{}
}

func newConn(w io.Writer, r io.Reader) *conn {
	return &conn{w: w, r: bufio.NewReaderSize(r, 1<<20), waiting: map[int64]chan message{}, closed: make(chan struct{})}
}

func (c *conn) readLoop() {
	defer close(c.closed)
	for {
		raw, err := c.r.ReadBytes(0)
		if err != nil {
			return
		}
		var m message
		if json.Unmarshal(raw[:len(raw)-1], &m) != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.waiting[m.ID]
			delete(c.waiting, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if c.onEvent != nil {
			c.onEvent(event{Method: m.Method, Params: m.Params, SessionID: m.SessionID})
		}
	}
}

func (c *conn) write(id int64, method, session string, params any) error {
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if session != "" {
		msg["sessionId"] = session
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.w.Write(append(b, 0))
	return err
}

// send fires a command without waiting for its result.
func (c *conn) send(method, session string, params any) {
	_ = c.write(c.nextID.Add(1), method, session, params)
}

// call sends a command and waits for its result.
func (c *conn) call(ctx context.Context, session, method string, params any, out any) error {
	id := c.nextID.Add(1)
	ch := make(chan message, 1)
	c.mu.Lock()
	c.waiting[id] = ch
	c.mu.Unlock()
	if err := c.write(id, method, session, params); err != nil {
		return err
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return errors.New(m.Error.Message)
		}
		if out != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, out)
		}
		return nil
	case <-c.closed:
		return errors.New("browser exited")
	case <-ctx.Done():
		return ctx.Err()
	}
}

type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	k := min(len(p), l.n)
	l.n -= k
	l.w.Write(p[:k])
	return len(p), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
