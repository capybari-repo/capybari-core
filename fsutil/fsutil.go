// Package fsutil provides safe, bounded file access relative to a scan root.
package fsutil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMaxRead is the default maximum number of bytes read from one file.
const DefaultMaxRead = 2 << 20

// ErrOutsideRoot is returned when a path escapes the scan root.
var ErrOutsideRoot = errors.New("path escapes scan root")

// Join resolves a slash-separated relative path under root and refuses
// anything that escapes it, including through symlinks.
func Join(root, rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, rel)
	}
	full := filepath.Join(root, clean)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if resolved != rootResolved && !strings.HasPrefix(resolved, rootResolved+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, rel)
	}
	return resolved, nil
}

// ReadFile reads at most max bytes (DefaultMaxRead when max <= 0) of a file
// under root. truncated reports whether the file was longer.
func ReadFile(root, rel string, max int64) (data []byte, truncated bool, err error) {
	if max <= 0 {
		max = DefaultMaxRead
	}
	p, err := Join(root, rel)
	if err != nil {
		return nil, false, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

// Exists reports whether rel exists under root.
func Exists(root, rel string) bool {
	p, err := Join(root, rel)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// IsBinary guesses whether content is binary by looking for NUL bytes in the
// first 8 KiB.
func IsBinary(b []byte) bool {
	if len(b) > 8192 {
		b = b[:8192]
	}
	return bytes.IndexByte(b, 0) >= 0
}

// CountLines counts newline-terminated lines (a final unterminated line counts).
func CountLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := bytes.Count(b, []byte{'\n'})
	if b[len(b)-1] != '\n' {
		n++
	}
	return n
}

// Lines calls fn for each line (1-based) until fn returns false.
func Lines(b []byte, fn func(n int, line string) bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	n := 0
	for sc.Scan() {
		n++
		if !fn(n, sc.Text()) {
			return
		}
	}
}

// ExcludedDirs are directory names never descended into: version-control
// internals, installed dependencies, virtual environments and build caches.
// Their contents are third-party or generated, not the project's source.
var ExcludedDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "bower_components": true, "jspm_packages": true,
	".venv": true, "venv": true, "__pycache__": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true, ".ruff_cache": true,
	".gradle": true, ".m2": true, ".idea": true, ".vscode-test": true,
	".next": true, ".nuxt": true, ".svelte-kit": true, ".turbo": true, ".parcel-cache": true, ".cache": true,
	".terraform": true, ".serverless": true, "coverage": true, ".nyc_output": true,
}
