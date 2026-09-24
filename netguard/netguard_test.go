package netguard

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostAllowed(t *testing.T) {
	allowed := []string{"api.osv.dev", "*.example.com"}
	for host, want := range map[string]bool{
		"api.osv.dev": true, "API.OSV.DEV": true, "evil.dev": false,
		"a.example.com": true, "example.com": false, "a.example.com.evil": false,
	} {
		if got := HostAllowed(allowed, host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestIsPrivate(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "192.168.0.1": true, "169.254.169.254": true,
		"::1": true, "fd00::1": true, "8.8.8.8": false, "1.1.1.1": false, "2606:4700::1111": false,
	} {
		if got := IsPrivate(net.ParseIP(ip)); got != want {
			t.Errorf("IsPrivate(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestClientEnforcesPolicyAndRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	rec := NewRecorder()

	c := NewClient(Policy{Capability: "cap", AllowedHosts: []string{"127.0.0.1"}, Recorder: rec})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if _, err := c.Get("http://localhost.invalid/"); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("expected ErrHostNotAllowed, got %v", err)
	}

	deny := NewClient(Policy{Capability: "cap", AllowedHosts: []string{"127.0.0.1"}, DenyPrivate: true, Recorder: rec})
	if _, err := deny.Get(srv.URL); !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("expected ErrPrivateAddress, got %v", err)
	}

	calls := rec.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	for _, c := range calls {
		switch c.Host {
		case "127.0.0.1":
			if c.Count != 1 {
				t.Errorf("127.0.0.1 count = %d", c.Count)
			}
		case "localhost.invalid":
			if c.Blocked != 1 || c.Count != 0 {
				t.Errorf("blocked call recorded wrong: %+v", c)
			}
		}
	}
}
