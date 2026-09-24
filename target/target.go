// Package target turns user input (a folder, an archive, a repository URL
// or a website URL) into an analyzer.Target. "What should I inspect?" is
// the only question the first interface asks (Unified Agent, Section 3).
package target

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/capybari/capybari-core/analyzer"
)

// Options control resolution.
type Options struct {
	// As forces the target kind ("repository" or "website").
	As analyzer.TargetKind
	// WorkDir is where archives are extracted and repositories cloned.
	// A temporary directory is created when empty.
	WorkDir string
	// MaxArchiveBytes bounds the total uncompressed archive size (default 1 GiB).
	MaxArchiveBytes int64
	// MaxArchiveFiles bounds the number of archive entries (default 200k).
	MaxArchiveFiles int
	// AllowClone permits cloning remote git repositories with the git binary.
	AllowClone bool
}

// Resolved is a target plus a cleanup function for temporary files.
type Resolved struct {
	Target  analyzer.Target
	Cleanup func()
}

var gitHosts = regexp.MustCompile(`^(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)$`)

// Resolve interprets input.
func Resolve(ctx context.Context, input string, o Options) (*Resolved, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, errors.New("nothing to inspect: give a folder, archive, repository URL or website URL")
	}
	if o.MaxArchiveBytes == 0 {
		o.MaxArchiveBytes = 1 << 30
	}
	if o.MaxArchiveFiles == 0 {
		o.MaxArchiveFiles = 200_000
	}
	noop := func() {}

	if u, ok := parseURL(input); ok {
		kind := o.As
		if kind == "" {
			kind = analyzer.TargetWebsite
			if looksLikeRepo(u) {
				kind = analyzer.TargetRepository
			}
		}
		if kind == analyzer.TargetWebsite {
			return &Resolved{Target: analyzer.Target{Kind: kind, Input: input, URL: u.String(), Display: u.Host}, Cleanup: noop}, nil
		}
		if !o.AllowClone {
			return nil, errors.New("cloning remote repositories is disabled")
		}
		dir, cleanup, err := workDir(o.WorkDir, "clone")
		if err != nil {
			return nil, err
		}
		if err := clone(ctx, u.String(), dir); err != nil {
			cleanup()
			return nil, err
		}
		return &Resolved{Target: analyzer.Target{Kind: analyzer.TargetRepository, Input: input, Root: dir, URL: u.String(), Display: repoDisplay(u)}, Cleanup: cleanup}, nil
	}

	st, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect %q: %w", input, err)
	}
	if o.As == analyzer.TargetWebsite {
		return nil, errors.New("a local path cannot be analysed as a website")
	}
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return &Resolved{Target: analyzer.Target{Kind: analyzer.TargetRepository, Input: input, Root: abs, Display: filepath.Base(abs)}, Cleanup: noop}, nil
	}
	lower := strings.ToLower(abs)
	switch {
	case strings.HasSuffix(lower, ".zip"), strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".tar"):
	default:
		return nil, fmt.Errorf("%q is a file; supported archives are .zip, .tar, .tar.gz and .tgz", input)
	}
	dir, cleanup, err := workDir(o.WorkDir, "archive")
	if err != nil {
		return nil, err
	}
	if err := Extract(abs, dir, o.MaxArchiveBytes, o.MaxArchiveFiles); err != nil {
		cleanup()
		return nil, err
	}
	root := singleTopDir(dir)
	name := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(filepath.Base(abs), ".zip"), ".tgz"), ".tar.gz")
	return &Resolved{Target: analyzer.Target{Kind: analyzer.TargetRepository, Input: input, Root: root, Display: name}, Cleanup: cleanup}, nil
}

func parseURL(s string) (*url.URL, bool) {
	if !strings.Contains(s, "://") {
		// Bare domains like "example.com" are websites unless they exist locally.
		if _, err := os.Stat(s); err == nil {
			return nil, false
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(/.*)?$`).MatchString(s) {
			return nil, false
		}
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, false
	}
	return u, true
}

func looksLikeRepo(u *url.URL) bool {
	if strings.HasSuffix(u.Path, ".git") {
		return true
	}
	if !gitHosts.MatchString(strings.ToLower(u.Hostname())) {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

func repoDisplay(u *url.URL) string {
	return strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
}

func workDir(base, prefix string) (string, func(), error) {
	d, err := os.MkdirTemp(base, "capybari-"+prefix+"-")
	if err != nil {
		return "", nil, err
	}
	return d, func() { os.RemoveAll(d) }, nil
}

func clone(ctx context.Context, repoURL, dir string) error {
	git, err := exec.LookPath("git")
	if err != nil {
		return errors.New("git is required to analyse a remote repository; install git or clone it yourself and pass the folder")
	}
	cmd := exec.CommandContext(ctx, git, "clone", "--quiet", "--depth", "200", "--single-branch", "--no-tags", "--", repoURL, dir)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// singleTopDir returns the only subdirectory when an archive wraps everything
// in one folder (as GitHub source downloads do).
func singleTopDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return dir
	}
	return filepath.Join(dir, entries[0].Name())
}

// Extract unpacks a zip or tar(.gz) archive into dst. It rejects absolute
// paths, path traversal and links, and enforces size and entry limits.
func Extract(archive, dst string, maxBytes int64, maxFiles int) error {
	lower := strings.ToLower(archive)
	if strings.HasSuffix(lower, ".zip") {
		return extractZip(archive, dst, maxBytes, maxFiles)
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	var total int64
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n++; n > maxFiles {
			return fmt.Errorf("archive has more than %d entries", maxFiles)
		}
		p, err := safePath(dst, h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxBytes {
				return fmt.Errorf("archive expands beyond %d bytes", maxBytes)
			}
			if err := writeFile(p, tr, h.Size); err != nil {
				return err
			}
		default:
			// Links, devices and other special entries are skipped for safety.
		}
	}
}

func extractZip(archive, dst string, maxBytes int64, maxFiles int) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > maxFiles {
		return fmt.Errorf("archive has more than %d entries", maxFiles)
	}
	var total int64
	for _, f := range zr.File {
		p, err := safePath(dst, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
			continue
		}
		if !f.Mode().IsRegular() {
			continue
		}
		total += int64(f.UncompressedSize64)
		if total > maxBytes {
			return fmt.Errorf("archive expands beyond %d bytes", maxBytes)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = writeFile(p, rc, int64(f.UncompressedSize64))
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func safePath(dst, name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry %q escapes the extraction directory", name)
	}
	return filepath.Join(dst, clean), nil
}

func writeFile(p string, r io.Reader, size int64) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	// Copy at most the declared size (+1 to detect lying headers).
	n, err := io.Copy(out, io.LimitReader(r, size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > size {
		err = fmt.Errorf("archive entry %s is larger than declared", filepath.Base(p))
	}
	return err
}
