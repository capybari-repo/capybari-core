package inventory

import (
	"path"
	"strings"
)

// languageByExt maps lower-case file extensions to languages.
var languageByExt = map[string]string{
	".go": "Go", ".py": "Python", ".pyi": "Python", ".ipynb": "Jupyter Notebook",
	".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
	".ts": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript", ".tsx": "TypeScript",
	".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".groovy": "Groovy", ".clj": "Clojure",
	".cs": "C#", ".fs": "F#", ".vb": "Visual Basic",
	".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
	".m": "Objective-C", ".mm": "Objective-C", ".swift": "Swift",
	".rs": "Rust", ".rb": "Ruby", ".erb": "Ruby", ".rake": "Ruby", ".php": "PHP", ".phtml": "PHP",
	".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hrl": "Erlang",
	".hs": "Haskell", ".ml": "OCaml", ".mli": "OCaml", ".elm": "Elm", ".lua": "Lua", ".r": "R", ".jl": "Julia",
	".pl": "Perl", ".pm": "Perl", ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".fish": "Shell", ".ps1": "PowerShell", ".psm1": "PowerShell", ".bat": "Batch", ".cmd": "Batch",
	".sql": "SQL", ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "SCSS", ".sass": "Sass", ".less": "Less",
	".vue": "Vue", ".svelte": "Svelte", ".astro": "Astro",
	".tf": "HCL", ".tfvars": "HCL", ".hcl": "HCL", ".bicep": "Bicep", ".nix": "Nix",
	".sol": "Solidity", ".zig": "Zig", ".nim": "Nim", ".cr": "Crystal", ".v": "V", ".d": "D",
	".proto": "Protocol Buffers", ".graphql": "GraphQL", ".gql": "GraphQL", ".thrift": "Thrift",
	".cob": "COBOL", ".cbl": "COBOL", ".f": "Fortran", ".f90": "Fortran", ".pas": "Pascal", ".abap": "ABAP", ".vbs": "VBScript",
	".asm": "Assembly", ".s": "Assembly",
	".yaml": "YAML", ".yml": "YAML", ".json": "JSON", ".toml": "TOML", ".xml": "XML", ".ini": "INI",
	".md": "Markdown", ".mdx": "MDX", ".rst": "reStructuredText", ".adoc": "AsciiDoc",
	".twig": "Twig", ".hbs": "Handlebars", ".ejs": "EJS", ".jinja": "Jinja", ".j2": "Jinja", ".liquid": "Liquid", ".cshtml": "Razor", ".razor": "Razor",
}

var languageByName = map[string]string{
	"dockerfile": "Dockerfile", "containerfile": "Dockerfile", "makefile": "Makefile", "gnumakefile": "Makefile",
	"cmakelists.txt": "CMake", "jenkinsfile": "Groovy", "rakefile": "Ruby", "gemfile": "Ruby", "vagrantfile": "Ruby", "podfile": "Ruby",
	"build.gradle": "Groovy", "build.gradle.kts": "Kotlin", "justfile": "Just",
}

// programming reports whether a language counts as program source (as
// opposed to data/markup/config formats).
var dataLanguages = map[string]bool{
	"YAML": true, "JSON": true, "TOML": true, "XML": true, "INI": true,
	"Markdown": true, "MDX": true, "reStructuredText": true, "AsciiDoc": true,
}

func languageOf(p string) string {
	base := strings.ToLower(path.Base(p))
	if l, ok := languageByName[base]; ok {
		return l
	}
	if strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") {
		return "Dockerfile"
	}
	return languageByExt[strings.ToLower(path.Ext(base))]
}

var assetExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".avif": true, ".ico": true, ".svg": true, ".bmp": true, ".tiff": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp3": true, ".wav": true, ".ogg": true, ".mp4": true, ".webm": true, ".mov": true,
	".pdf": true, ".psd": true, ".sketch": true, ".fig": true,
}

var dataExt = map[string]bool{
	".csv": true, ".tsv": true, ".parquet": true, ".avro": true, ".db": true, ".sqlite": true, ".sqlite3": true, ".xlsx": true, ".xls": true, ".ndjson": true, ".jsonl": true,
}

var buildNames = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "pnpm-workspace.yaml": true, "bun.lockb": true, "bun.lock": true,
	"go.mod": true, "go.sum": true, "go.work": true, "cargo.toml": true, "cargo.lock": true,
	"pyproject.toml": true, "setup.py": true, "setup.cfg": true, "pipfile": true, "pipfile.lock": true, "poetry.lock": true, "uv.lock": true, "pdm.lock": true,
	"gemfile": true, "gemfile.lock": true, "composer.json": true, "composer.lock": true,
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "settings.gradle": true, "settings.gradle.kts": true, "gradle.lockfile": true,
	"makefile": true, "gnumakefile": true, "cmakelists.txt": true, "justfile": true, "rakefile": true,
	"mix.exs": true, "mix.lock": true, "pubspec.yaml": true, "pubspec.lock": true, "package.swift": true, "package.resolved": true, "podfile": true, "podfile.lock": true,
	"deno.json": true, "deno.lock": true, "lerna.json": true, "nx.json": true, "turbo.json": true, "rush.json": true, "packages.lock.json": true, "directory.packages.props": true,
}

func isRequirements(base string) bool {
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}
