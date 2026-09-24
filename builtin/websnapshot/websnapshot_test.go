package websnapshot_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/capybari/capybari-core/analyzertest"
	"github.com/capybari/capybari-core/builtin/websnapshot"
	"github.com/capybari/capybari-core/facts"
)

func TestSnapshot(t *testing.T) {
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
