// Package inventory is the built-in Repository Inventory capability. It is
// the file-level foundation every repository capability builds on, so it
// ships with capybari-core instead of in its own analyzer repository.
package inventory

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-core/finding"
	"github.com/capybari/capybari-core/fsutil"
)

//go:embed capability.yaml
var capabilityYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

// MaxFiles bounds the inventory size.
const MaxFiles = 100_000

// largeFile is the size above which a committed file is reported.
const largeFile = 10 << 20

// Analyzer implements the inventory capability.
type Analyzer struct{}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

// Analyze implements analyzer.Analyzer.
func (*Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	root := in.Target.Root
	inv := &facts.Inventory{KindCounts: map[facts.FileKind]int{}}
	paths, method, excluded, err := list(ctx, root)
	if err != nil {
		return nil, err
	}
	inv.Method = method
	inv.ExcludedDirs = excluded
	if len(paths) > MaxFiles {
		paths = paths[:MaxFiles]
		inv.Truncated = true
	}

	var findings []finding.Finding
	vendoredRoots := map[string]int{}
	langs := map[string]*facts.LanguageStat{}
	for _, rel := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		f := facts.File{Path: rel, Size: info.Size(), Language: languageOf(rel)}
		var head []byte
		if info.Size() <= fsutil.DefaultMaxRead {
			data, _, err := fsutil.ReadFile(root, rel, fsutil.DefaultMaxRead)
			if err == nil {
				head = data
				f.Binary = fsutil.IsBinary(data)
				if !f.Binary {
					f.Lines = fsutil.CountLines(data)
				}
			}
		} else {
			data, _, err := fsutil.ReadFile(root, rel, 8192)
			if err == nil {
				head = data
				f.Binary = fsutil.IsBinary(data)
			}
		}
		f.Kind = classify(rel, f, head)
		if f.Binary && f.Kind == facts.KindSource {
			f.Kind = facts.KindOther
		}
		if f.Kind == facts.KindVendored {
			vendoredRoots[vendorRoot(rel)]++
		}
		if info.Size() >= largeFile && f.Kind != facts.KindVendored {
			findings = append(findings, finding.Finding{
				Dimension: finding.DimMaintainability, Category: "repository-hygiene", Severity: finding.Low, Confidence: finding.ConfidenceHigh,
				Title:       fmt.Sprintf("Large file committed (%d MB)", info.Size()>>20),
				Description: "Large files slow down cloning and CI and often belong in artifact or object storage (or Git LFS).",
				Evidence:    []finding.Evidence{{Location: finding.Location{Path: rel}}},
				Rule:        &finding.Rule{ID: "large-file"},
				Remediation: &finding.Remediation{Summary: "Move the file to Git LFS or external storage if it is not source.", Automatable: false},
			})
		}
		inv.Files = append(inv.Files, f)
		inv.KindCounts[f.Kind]++
		inv.TotalFiles++
		inv.TotalBytes += f.Size
		inv.TotalLines += f.Lines
		if f.Language != "" && (f.Kind == facts.KindSource || f.Kind == facts.KindTest) && !dataLanguages[f.Language] {
			ls := langs[f.Language]
			if ls == nil {
				ls = &facts.LanguageStat{Language: f.Language}
				langs[f.Language] = ls
			}
			ls.Files++
			ls.Lines += f.Lines
		}
	}
	for dir, n := range vendoredRoots {
		if method != "git-ls-files" || dir == "" {
			continue
		}
		findings = append(findings, finding.Finding{
			Dimension: finding.DimMaintainability, Category: "repository-hygiene", Severity: finding.Low, Confidence: finding.ConfidenceHigh,
			Title:       "Third-party dependencies committed to the repository",
			Description: fmt.Sprintf("%d files under %s/ are tracked in git. Committed dependencies are hard to update and audit.", n, dir),
			Evidence:    []finding.Evidence{{Location: finding.Location{Path: dir + "/"}}},
			Rule:        &finding.Rule{ID: "committed-dependencies"},
			Remediation: &finding.Remediation{Summary: "Install dependencies from a lockfile at build time instead of committing them, unless vendoring is a deliberate policy.", Automatable: false},
			FalsePositiveGuidance: "Go vendor/ directories and some embedded-systems projects vendor dependencies deliberately.",
		})
	}

	var total int
	for _, l := range langs {
		total += l.Lines
	}
	for _, l := range langs {
		if total > 0 {
			l.Share = float64(l.Lines) / float64(total)
		}
		inv.Languages = append(inv.Languages, *l)
	}
	sort.Slice(inv.Languages, func(i, j int) bool {
		if inv.Languages[i].Lines != inv.Languages[j].Lines {
			return inv.Languages[i].Lines > inv.Languages[j].Lines
		}
		return inv.Languages[i].Language < inv.Languages[j].Language
	})

	res := &analyzer.Result{
		Evidence: map[string]any{facts.KeyInventory: inv},
		Findings: findings,
		Summary:  fmt.Sprintf("%d files, %d lines, %d languages (listed via %s)", inv.TotalFiles, inv.TotalLines, len(inv.Languages), method),
	}
	if inv.Truncated {
		res.Limitations = append(res.Limitations, fmt.Sprintf("Repository has more than %d files; only the first %d were inventoried.", MaxFiles, MaxFiles))
	}
	if method == "walk" {
		res.Limitations = append(res.Limitations, "No git metadata was available, so .gitignore rules were not applied; built-in exclusions were used instead.")
	}
	return res, nil
}

// list returns slash-separated relative paths. It prefers `git ls-files`
// (tracked plus untracked-but-not-ignored files) and falls back to a walk.
func list(ctx context.Context, root string) (paths []string, method string, excluded []string, err error) {
	if _, statErr := os.Stat(filepath.Join(root, ".git")); statErr == nil {
		if git, lookErr := exec.LookPath("git"); lookErr == nil {
			cmd := exec.CommandContext(ctx, git, "-C", root, "-c", "core.quotepath=off", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
			if out, runErr := cmd.Output(); runErr == nil {
				seen := map[string]bool{}
				for _, p := range bytes.Split(out, []byte{0}) {
					s := string(p)
					if s == "" || seen[s] {
						continue
					}
					seen[s] = true
					paths = append(paths, s)
				}
				sort.Strings(paths)
				return paths, "git-ls-files", nil, nil
			}
		}
	}
	exSet := map[string]bool{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && fsutil.ExcludedDirs[d.Name()] {
				exSet[rel] = true
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		paths = append(paths, rel)
		if len(paths) > MaxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	for d := range exSet {
		excluded = append(excluded, d)
	}
	sort.Strings(excluded)
	sort.Strings(paths)
	return paths, "walk", excluded, err
}

var vendorDirs = []string{"node_modules", "vendor", "third_party", "thirdparty", "third-party", "bower_components", "external", "extern", "deps", "Pods", "Carthage", "site-packages", ".venv", "venv", "packages"}

func segments(rel string) []string { return strings.Split(rel, "/") }

func vendorRoot(rel string) string {
	segs := segments(rel)
	for i, s := range segs[:len(segs)-1] {
		for _, v := range vendorDirs {
			if s == v {
				return strings.Join(segs[:i+1], "/")
			}
		}
	}
	return ""
}

func hasSegment(rel string, names ...string) bool {
	segs := segments(rel)
	for _, s := range segs[:len(segs)-1] {
		ls := strings.ToLower(s)
		for _, n := range names {
			if ls == n {
				return true
			}
		}
	}
	return false
}

var generatedMarkers = [][]byte{
	[]byte("Code generated"), []byte("DO NOT EDIT"), []byte("@generated"), []byte("<auto-generated"), []byte("This file is automatically generated"),
}

func classify(rel string, f facts.File, head []byte) facts.FileKind {
	lower := strings.ToLower(rel)
	base := path.Base(lower)
	ext := path.Ext(base)

	// Vendored and generated content first: it overrides everything else.
	if hasSegment(rel, "node_modules", "vendor", "third_party", "thirdparty", "third-party", "bower_components", "pods", "carthage", "site-packages") {
		return facts.KindVendored
	}
	if hasSegment(rel, "dist", "out", "target", ".next", "__generated__", "generated", "gen") ||
		strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".min.css") || strings.HasSuffix(base, ".map") ||
		strings.HasSuffix(base, ".pb.go") || strings.HasSuffix(base, "_pb2.py") || strings.HasSuffix(base, ".g.dart") ||
		strings.Contains(base, "_generated.") || strings.HasSuffix(base, ".designer.cs") {
		return facts.KindGenerated
	}
	if len(head) > 0 && !f.Binary {
		h := head[:min(len(head), 1024)]
		for _, m := range generatedMarkers {
			if bytes.Contains(h, m) {
				return facts.KindGenerated
			}
		}
	}

	switch {
	case strings.HasPrefix(lower, ".github/workflows/"), base == ".gitlab-ci.yml", strings.HasPrefix(lower, ".circleci/"),
		base == "jenkinsfile", base == "azure-pipelines.yml", base == ".travis.yml", base == "bitbucket-pipelines.yml",
		strings.HasPrefix(lower, ".buildkite/"), base == ".drone.yml", base == "cloudbuild.yaml", base == "cloudbuild.yml",
		strings.HasPrefix(lower, ".woodpecker"), base == "appveyor.yml", base == "codemagic.yaml":
		return facts.KindCI
	case strings.HasPrefix(base, "dockerfile"), strings.HasSuffix(base, ".dockerfile"), base == "containerfile",
		strings.HasPrefix(base, "docker-compose"), base == "compose.yaml", base == "compose.yml", base == ".dockerignore":
		return facts.KindContainer
	case ext == ".tf", ext == ".tfvars", ext == ".bicep", base == "chart.yaml", base == "pulumi.yaml", base == "serverless.yml", base == "serverless.yaml",
		base == "template.yaml" && hasSegment(rel, "cloudformation", "cfn", "sam"),
		base == "kustomization.yaml", hasSegment(rel, "k8s", "kubernetes", "helm", "charts", "manifests", "terraform", "ansible") && (ext == ".yaml" || ext == ".yml" || ext == ".tpl" || ext == ".hcl"):
		return facts.KindIaC
	}

	if isTest(lower, base) {
		return facts.KindTest
	}
	if buildNames[base] || isRequirements(base) || strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".sln") || strings.HasSuffix(base, ".gemspec") ||
		strings.HasSuffix(base, ".cabal") || strings.HasPrefix(base, "webpack.config.") || strings.HasPrefix(base, "vite.config.") || strings.HasPrefix(base, "rollup.config.") {
		return facts.KindBuild
	}
	switch {
	case ext == ".md" || ext == ".mdx" || ext == ".rst" || ext == ".adoc" || ext == ".txt" && hasSegment(rel, "docs", "doc", "documentation"),
		strings.HasPrefix(base, "readme"), strings.HasPrefix(base, "license"), strings.HasPrefix(base, "licence"), strings.HasPrefix(base, "changelog"),
		strings.HasPrefix(base, "contributing"), strings.HasPrefix(base, "code_of_conduct"), strings.HasPrefix(base, "security.md"), base == "notice",
		hasSegment(rel, "docs", "doc", "documentation") && (ext == ".html" || ext == ".png" || ext == ".svg"):
		return facts.KindDocs
	case assetExt[ext]:
		return facts.KindAsset
	case dataExt[ext]:
		return facts.KindData
	}
	if f.Language != "" && !dataLanguages[f.Language] {
		return facts.KindSource
	}
	switch ext {
	case ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".xml", ".plist", ".editorconfig", ".lock":
		return facts.KindConfig
	}
	if strings.HasPrefix(base, ".") || strings.HasPrefix(base, ".env") {
		return facts.KindConfig
	}
	return facts.KindOther
}

func isTest(lower, base string) bool {
	if hasSegment(lower, "test", "tests", "__tests__", "spec", "specs", "testing", "e2e", "cypress", "playwright", "testdata", "fixtures", "__mocks__") {
		return true
	}
	switch {
	case strings.HasSuffix(base, "_test.go"), strings.HasSuffix(base, "_test.py"), strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"),
		strings.Contains(base, ".test."), strings.Contains(base, ".spec."), strings.Contains(base, "_spec."),
		strings.HasSuffix(base, "test.java"), strings.HasSuffix(base, "tests.java"), strings.HasSuffix(base, "test.kt"),
		strings.HasSuffix(base, "tests.cs"), strings.HasSuffix(base, "test.cs"), strings.HasSuffix(base, "test.php"), strings.HasSuffix(base, "_test.rb"),
		strings.HasSuffix(base, "_test.exs"), strings.HasSuffix(base, "_test.dart"), strings.HasSuffix(base, "tests.swift"), strings.HasSuffix(base, "_test.rs"):
		return true
	}
	return false
}
