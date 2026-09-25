package websnapshot_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/capybari-repo/capybari-core/analyzertest"
	"github.com/capybari-repo/capybari-core/builtin/websnapshot"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/render"
)

func TestSnapshot(t *testing.T) {
	t.Setenv("CAPYBARI_RENDER", "0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "secret", HttpOnly: true})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx/1.18.0")
		w.Write([]byte(`<!doctype html><html><head><title> Demo Site </title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/themes/x/style.css">
<script src="https://cdn.example.net/jquery-3.5.1.min.js" integrity="sha384-x"></script>
</head><body>hi</body></html>`))
	}))
	defer srv.Close()

	r := analyzertest.Run(t, websnapshot.New(), analyzertest.Website(srv.URL+"/old"), analyzertest.Options{Online: true})
	var ws facts.WebSnapshot
	if !r.Fact(facts.KeyWebSnapshot, &ws) {
		t.Fatal("no snapshot")
	}
	if ws.Status != 200 || ws.FinalURL != srv.URL+"/" || len(ws.Redirects) != 1 {
		t.Fatalf("status/final/redirects: %d %s %v", ws.Status, ws.FinalURL, ws.Redirects)
	}
	if ws.Title != "Demo Site" || ws.Meta["generator"] != "WordPress 6.4.2" || ws.Header("server") != "nginx/1.18.0" {
		t.Fatalf("parse: title=%q meta=%v", ws.Title, ws.Meta)
	}
	if len(ws.Resources) != 2 || !ws.Resources[1].SRI {
		t.Fatalf("resources: %+v", ws.Resources)
	}
	if len(ws.Cookies) != 1 || !ws.Cookies[0].HTTPOnly || ws.Cookies[0].Secure {
		t.Fatalf("cookies: %+v", ws.Cookies)
	}
	if ws.Body != "" {
		t.Fatal("report facts must not carry the page body")
	}
	if !r.DataBoundary.LeftMachine || len(r.DataBoundary.Disclosures) != 1 {
		t.Fatalf("data boundary: %+v", r.DataBoundary)
	}
}

func TestCrawlIsPolite(t *testing.T) {
	t.Setenv("CAPYBARI_RENDER", "0")
	var mu sync.Mutex
	requested := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/robots.txt":
			w.Write([]byte("User-agent: *\nDisallow: /private\n"))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body>
<a href="/about">About</a> <a href="/about#team">Team</a> <a href="/private/plans">Plans</a>
<a href="/logout">Log out</a> <a href="/wp-login.php?action=logout">Log out 2</a> <a href="/brochure.pdf">PDF</a> <a href="https://other.example/x">Elsewhere</a>
<a href="mailto:a@b.c">Mail</a> <a href="/blog">Blog</a></body></html>`))
		case "/about", "/blog":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>` + r.URL.Path + `</title><meta name="generator" content="Hugo 0.1"></head><body><p>Some words here.</p><script>ignored()</script></body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, st := analyzertest.RunState(t, websnapshot.New(), analyzertest.Website(srv.URL), analyzertest.Options{Online: true})
	var ws facts.WebSnapshot
	st.Get(facts.KeyWebSnapshot, &ws)
	if len(ws.Pages) != 2 {
		t.Fatalf("pages = %+v", ws.Pages)
	}
	for _, p := range ws.Pages {
		if p.Words != 4 || p.Generator != "Hugo 0.1" || strings.Contains(p.Text, "ignored") {
			t.Fatalf("page not reduced correctly: %+v", p)
		}
	}
	for _, forbidden := range []string{"/private/plans", "/logout", "/wp-login.php", "/brochure.pdf"} {
		if requested[forbidden] {
			t.Errorf("crawler requested %s", forbidden)
		}
	}
	// Reports never carry page markup or text.
	r := analyzertest.Run(t, websnapshot.New(), analyzertest.Website(srv.URL), analyzertest.Options{Online: true})
	var pub facts.WebSnapshot
	r.Fact(facts.KeyWebSnapshot, &pub)
	if len(pub.Pages) != 2 || pub.Pages[0].HTML != "" || pub.Pages[0].Text != "" || len(pub.Links) != 0 {
		t.Fatalf("public fact leaks page content: %+v", pub.Pages)
	}
}

func TestJavaScriptPageIsRendered(t *testing.T) {
	if render.Find() == "" {
		t.Skip("no headless Chromium available")
	}
	words := strings.Repeat("genuine product description words ", 50)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/about":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>App</title></head><body><div id="root">Loading...</div><script src="/app.js"></script></body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`document.getElementById("root").innerHTML = "<p>` + words + `</p><a href='/about'>About</a>";`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, st := analyzertest.RunState(t, websnapshot.New(), analyzertest.Website(srv.URL), analyzertest.Options{Online: true})
	var ws facts.WebSnapshot
	st.Get(facts.KeyWebSnapshot, &ws)
	if !ws.Rendered || !strings.Contains(ws.Body, "genuine product description") {
		t.Fatalf("front page not rendered: rendered=%v body=%.200s", ws.Rendered, ws.Body)
	}
	if len(ws.Pages) != 1 || !ws.Pages[0].Rendered || ws.Pages[0].Words < 150 {
		t.Fatalf("linked page (only discoverable after rendering) not rendered: %+v", ws.Pages)
	}
	if ws.RenderRequests < 2 {
		t.Fatalf("render requests not counted: %d", ws.RenderRequests)
	}
}

func TestRenderingDisabledIsExplained(t *testing.T) {
	t.Setenv("CAPYBARI_RENDER", "0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><div id="root">Loading...</div><script src="/app.js"></script></body></html>`))
	}))
	defer srv.Close()
	r := analyzertest.Run(t, websnapshot.New(), analyzertest.Website(srv.URL), analyzertest.Options{Online: true})
	run, _ := r.Capability("web-snapshot")
	if !strings.Contains(strings.Join(run.Limitations, "|"), "no headless Chromium is installed") {
		t.Fatalf("missing explanation: %v", run.Limitations)
	}
}
