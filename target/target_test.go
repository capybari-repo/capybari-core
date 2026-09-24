package target

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/capybari/capybari-core/analyzer"
)

func TestResolveKinds(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	cases := []struct {
		in   string
		as   analyzer.TargetKind
		kind analyzer.TargetKind
		url  string
	}{
		{in: "https://example.com", kind: analyzer.TargetWebsite, url: "https://example.com"},
		{in: "example.com", kind: analyzer.TargetWebsite, url: "https://example.com"},
		{in: "https://github.com/org/repo", as: analyzer.TargetWebsite, kind: analyzer.TargetWebsite, url: "https://github.com/org/repo"},
		{in: dir, kind: analyzer.TargetRepository},
	}
	for _, c := range cases {
		r, err := Resolve(ctx, c.in, Options{As: c.as})
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if r.Target.Kind != c.kind || (c.url != "" && r.Target.URL != c.url) {
			t.Errorf("%s: got %+v", c.in, r.Target)
		}
		r.Cleanup()
	}
	if _, err := Resolve(ctx, "https://github.com/org/repo", Options{}); err == nil {
		t.Error("repository URL should require AllowClone")
	}
	if !looksLikeRepo(mustURL("https://github.com/org/repo")) || looksLikeRepo(mustURL("https://github.com/org")) {
		t.Error("looksLikeRepo misclassifies")
	}
}

func TestZipSlipRejected(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../evil.txt")
	w.Write([]byte("x"))
	zw.Close()
	arc := filepath.Join(t.TempDir(), "a.zip")
	os.WriteFile(arc, buf.Bytes(), 0o644)
	if err := Extract(arc, t.TempDir(), 1<<20, 100); err == nil {
		t.Fatal("expected traversal error")
	}
}

func TestTarExtractAndLimits(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, typ byte, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: typ, Size: int64(len(body)), Mode: 0o644, Linkname: "/etc/passwd"})
		tw.Write([]byte(body))
	}
	add("proj/", tar.TypeDir, "")
	add("proj/main.go", tar.TypeReg, "package main\n")
	add("proj/link", tar.TypeSymlink, "")
	tw.Close()
	arc := filepath.Join(t.TempDir(), "p.tar")
	os.WriteFile(arc, buf.Bytes(), 0o644)

	r, err := Resolve(context.Background(), arc, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cleanup()
	if filepath.Base(r.Target.Root) != "proj" {
		t.Fatalf("root = %s", r.Target.Root)
	}
	if _, err := os.Stat(filepath.Join(r.Target.Root, "main.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(r.Target.Root, "link")); err == nil {
		t.Fatal("symlink should not be extracted")
	}
	if err := Extract(arc, t.TempDir(), 5, 100); err == nil {
		t.Fatal("expected size limit error")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
