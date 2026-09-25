package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestRenderRunsJavaScriptThroughOurClient(t *testing.T) {
	chrome := Find()
	if chrome == "" {
		t.Skip("no headless Chromium available")
	}
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><div id="root">Loading...</div><img src="/logo.png"><script src="/app.js"></script></body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/api/copy").then(r => r.json()).then(d => {
  document.getElementById("root").innerHTML = "<h1>" + d.title + "</h1><p>" + d.text + "</p><a href='/pricing'>Pricing</a>";
});`))
		case "/api/copy":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"title":"Rendered by JavaScript","text":"` + strings.Repeat("real words here ", 60) + `"}`))
		case "/logo.png":
			w.Write([]byte("png"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := Page(context.Background(), chrome, srv.Client(), srv.URL+"/", Options{NoSandbox: os.Geteuid() == 0})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.HTML, "Rendered by JavaScript") || !strings.Contains(res.HTML, `href="/pricing"`) {
		t.Fatalf("page not rendered: %.300s", res.HTML)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["/app.js"] != 1 || seen["/api/copy"] != 1 {
		t.Fatalf("scripts and API calls must go through our client: %v", seen)
	}
	if seen["/logo.png"] != 0 {
		t.Fatal("images must not be fetched")
	}
	if res.Requests != 3 {
		t.Fatalf("counts: %+v", res)
	}
}

func TestWanted(t *testing.T) {
	for typ, want := range map[string]bool{"Document": true, "Script": true, "XHR": true, "Fetch": true, "Stylesheet": true, "Image": false, "Font": false, "Media": false, "WebSocket": false} {
		if wanted(typ) != want {
			t.Errorf("%s: %v", typ, !want)
		}
	}
}

func TestIsTracker(t *testing.T) {
	for u, want := range map[string]bool{
		"https://www.googletagmanager.com/gtag/js?id=G-1": true,
		"https://region1.analytics.google.com/g/collect":  true,
		"https://z.clarity.ms/collect":                    true,
		"https://cdn.jsdelivr.net/npm/react":              false,
		"https://app.example.com/api/content":             false,
	} {
		if IsTracker(u) != want {
			t.Errorf("%s: %v", u, !want)
		}
	}
}
