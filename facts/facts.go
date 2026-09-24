// Package facts defines the shared evidence shapes that capabilities publish
// and consume. Analyzer repositories depend only on capybari-core, never on
// each other, so any evidence used by more than one capability lives here.
package facts

import "time"

// Well-known evidence keys.
const (
	KeyInventory    = "inventory"
	KeyFingerprint  = "fingerprint"
	KeyTechnologies = "technologies"
	KeyDependencies = "dependencies"
	KeyArchitecture = "architecture"
	KeyCodeHealth   = "code-health"
	KeyWebSnapshot  = "web-snapshot"
)

// FileKind classifies a file in the repository inventory.
type FileKind string

const (
	KindSource    FileKind = "source"
	KindTest      FileKind = "test"
	KindConfig    FileKind = "config"
	KindDocs      FileKind = "docs"
	KindCI        FileKind = "ci"
	KindIaC       FileKind = "iac"
	KindContainer FileKind = "container"
	KindBuild     FileKind = "build"
	KindData      FileKind = "data"
	KindAsset     FileKind = "asset"
	KindGenerated FileKind = "generated"
	KindVendored  FileKind = "vendored"
	KindOther     FileKind = "other"
)

// File is one entry of the repository inventory. Paths are slash-separated
// and relative to the repository root.
type File struct {
	Path     string   `json:"path"`
	Size     int64    `json:"size"`
	Lines    int      `json:"lines,omitempty"`
	Language string   `json:"language,omitempty"`
	Kind     FileKind `json:"kind"`
	Binary   bool     `json:"binary,omitempty"`
}

// LanguageStat aggregates files and lines per language.
type LanguageStat struct {
	Language string  `json:"language"`
	Files    int     `json:"files"`
	Lines    int     `json:"lines"`
	Share    float64 `json:"share"` // share of source lines, 0..1
}

// Inventory is published by the inventory capability.
type Inventory struct {
	Files        []File           `json:"files"`
	Languages    []LanguageStat   `json:"languages"`
	KindCounts   map[FileKind]int `json:"kind_counts"`
	TotalFiles   int              `json:"total_files"`
	TotalBytes   int64            `json:"total_bytes"`
	TotalLines   int              `json:"total_lines"`
	ExcludedDirs []string         `json:"excluded_dirs,omitempty"`
	Truncated    bool             `json:"truncated,omitempty"`
	Method       string           `json:"method"` // "git-ls-files" or "walk"
}

// Filter returns the files whose kind is one of kinds (all files when empty).
func (inv *Inventory) Filter(kinds ...FileKind) []File {
	if len(kinds) == 0 {
		return inv.Files
	}
	var out []File
	for _, f := range inv.Files {
		for _, k := range kinds {
			if f.Kind == k {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// Runtime is a language runtime and, when declared, its version.
type Runtime struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"` // file that declared it
}

// Fingerprint is the compact identity of a repository (Project Fingerprint).
type Fingerprint struct {
	Name            string    `json:"name"`
	PrimaryLanguage string    `json:"primary_language,omitempty"`
	ProjectTypes    []string  `json:"project_types"`
	PackageManagers []string  `json:"package_managers,omitempty"`
	BuildSystems    []string  `json:"build_systems,omitempty"`
	Runtimes        []Runtime `json:"runtimes,omitempty"`
	Manifests       []string  `json:"manifests,omitempty"`
	EntryPoints     []string  `json:"entry_points,omitempty"`
	Workspaces      []string  `json:"workspaces,omitempty"`
	Monorepo        bool      `json:"monorepo"`
	HasTests        bool      `json:"has_tests"`
	HasCI           []string  `json:"ci,omitempty"`
	HasContainers   bool      `json:"has_containers"`
	HasIaC          []string  `json:"iac,omitempty"`
	HasDocs         bool      `json:"has_docs"`
	License         string    `json:"license,omitempty"`
	Git             *GitInfo  `json:"git,omitempty"`
	Size            string    `json:"size"` // tiny, small, medium, large, very-large
	Digest          string    `json:"digest"`
}

// GitInfo summarises repository history when a .git directory is present.
type GitInfo struct {
	Commits      int       `json:"commits"`
	Contributors int       `json:"contributors"`
	FirstCommit  time.Time `json:"first_commit,omitzero"`
	LastCommit   time.Time `json:"last_commit,omitzero"`
	Branch       string    `json:"branch,omitempty"`
	Head         string    `json:"head,omitempty"`
	Shallow      bool      `json:"shallow,omitempty"`
}

// Technology is a detected language, framework, library, service or tool.
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"` // language, framework, library, runtime, database, cms, analytics, cdn, hosting, server, ui, testing, build, ci, infrastructure, ai-builder, ...
	Version    string   `json:"version,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
	Website    string   `json:"website,omitempty"`
	// EOL is set when the detected version is known to be end-of-life.
	EOL string `json:"eol,omitempty"`
}

// Technologies is published by tech-detect (repositories) and web-tech (websites).
type Technologies struct {
	Items []Technology `json:"items"`
}

// Names returns the lower-cased technology names, for condition matching.
func (t *Technologies) Names() []string {
	out := make([]string, 0, len(t.Items))
	for _, it := range t.Items {
		out = append(out, it.Name)
	}
	return out
}

// Package is one dependency.
type Package struct {
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Ecosystem string   `json:"ecosystem"` // OSV ecosystem name, e.g. npm, PyPI, Go
	PURL      string   `json:"purl,omitempty"`
	Locations []string `json:"locations"`
	Direct    *bool    `json:"direct,omitempty"`
	Dev       bool     `json:"dev,omitempty"`
	Parents   []string `json:"parents,omitempty"`
}

// Manifest is a dependency declaration file that was parsed.
type Manifest struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
	Lockfile  bool   `json:"lockfile"`
	Extractor string `json:"extractor"`
	Packages  int    `json:"packages"`
	Error     string `json:"error,omitempty"`
}

// Dependencies is published by the dependencies capability.
type Dependencies struct {
	Packages  []Package  `json:"packages"`
	Manifests []Manifest `json:"manifests"`
}

// ArchNode is a module/package in the architecture graph.
type ArchNode struct {
	ID       string `json:"id"`
	Language string `json:"language,omitempty"`
	Files    int    `json:"files"`
	Lines    int    `json:"lines"`
	Layer    string `json:"layer,omitempty"`
}

// ArchEdge is a dependency from one module to another.
type ArchEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Weight int    `json:"weight"`
}

// Architecture is published by the architecture capability.
type Architecture struct {
	Nodes    []ArchNode `json:"nodes"`
	Edges    []ArchEdge `json:"edges"`
	Cycles   [][]string `json:"cycles,omitempty"`
	External []string   `json:"external,omitempty"`
	Mermaid  string     `json:"mermaid,omitempty"`
}

// TLSInfo describes the TLS connection used for a website snapshot.
type TLSInfo struct {
	Version      string    `json:"version"`
	CipherSuite  string    `json:"cipher_suite"`
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	NotAfter     time.Time `json:"not_after,omitzero"`
	VerifyError  string    `json:"verify_error,omitempty"`
}

// Cookie is a cookie set by the website, without its value.
type Cookie struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// Resource is a sub-resource referenced by the page (script, stylesheet...).
type Resource struct {
	Kind string `json:"kind"` // script, stylesheet, link, iframe, img
	URL  string `json:"url"`
	SRI  bool   `json:"sri,omitempty"`
}

// WebSnapshot is published by the built-in web-snapshot capability. It is a
// single passive GET of the site's front page plus its redirect chain.
type WebSnapshot struct {
	RequestedURL string              `json:"requested_url"`
	FinalURL     string              `json:"final_url"`
	Status       int                 `json:"status"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body,omitempty"`
	BodyBytes    int                 `json:"body_bytes"`
	Truncated    bool                `json:"truncated,omitempty"`
	ContentType  string              `json:"content_type,omitempty"`
	Redirects    []string            `json:"redirects,omitempty"`
	HTTPSUpgrade *bool               `json:"https_upgrade,omitempty"` // does http:// redirect to https://
	TLS          *TLSInfo            `json:"tls,omitempty"`
	Cookies      []Cookie            `json:"cookies,omitempty"`
	Title        string              `json:"title,omitempty"`
	Meta         map[string]string   `json:"meta,omitempty"`
	Resources    []Resource          `json:"resources,omitempty"`
	FetchedAt    time.Time           `json:"fetched_at"`
	DurationMS   int64               `json:"duration_ms"`
}

// Header returns the first value of a header, case-insensitively.
func (w *WebSnapshot) Header(name string) string {
	for k, v := range w.Headers {
		if equalFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
