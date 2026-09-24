package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/fsutil"
)

// TargetDigest cheaply fingerprints a repository's current content using
// paths, sizes and modification times, plus the checked-out git commit.
// It is used as a cache key, not as a security measure.
func TargetDigest(t analyzer.Target) string {
	if t.Kind != analyzer.TargetRepository || t.Root == "" {
		return ""
	}
	h := sha256.New()
	_ = filepath.WalkDir(t.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != t.Root && fsutil.ExcludedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(t.Root, p)
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if head, err := os.ReadFile(filepath.Join(t.Root, ".git", "HEAD")); err == nil {
		h.Write(head)
		if ref, ok := strings.CutPrefix(strings.TrimSpace(string(head)), "ref: "); ok {
			if sha, err := os.ReadFile(filepath.Join(t.Root, ".git", filepath.FromSlash(ref))); err == nil {
				h.Write(sha)
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
