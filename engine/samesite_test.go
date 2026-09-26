package engine

import "testing"

// Redirect hosts are allowed only within the target's registered domain.
func TestSameSite(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"www.google.com", "google.com", true},
		{"shop.example.co.uk", "example.co.uk", true},
		{"evil.com", "google.com", false},
		{"google.com.evil.com", "google.com", false},
		{"example.co.uk", "other.co.uk", false},
	} {
		if got := sameSite(c.a, c.b); got != c.want {
			t.Errorf("sameSite(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
