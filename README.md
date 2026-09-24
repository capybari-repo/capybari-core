# capybari-core

**Capybari Source Intelligence: the shared analysis engine.**

`capybari-core` is the foundation every Capybari Source Intelligence capability builds on. It contains no product UI. The [`capybari`](https://github.com/capybari-repo/capybari-cli) CLI, the GitHub Action and the hosted service all run this same engine.

| Package | Purpose |
|---|---|
| `analyzer` | The Analyzer API (v0): `Analyzer`, `Capability` metadata (`capability.yaml`), `Input`, `Result`. |
| `finding` | The common finding schema: severity, confidence, evidence, rule, remediation, stable IDs. |
| `facts` | Shared evidence shapes (inventory, fingerprint, technologies, dependencies, architecture, web snapshot). Analyzers exchange evidence through these types and never import each other. |
| `engine` | Capability registry, dependency-aware planner, parallel orchestrator, caching hooks, score aggregation, recommendations ("What else can we tell you?") and the data-boundary record. |
| `report` | The unified report and its exporters: JSON (canonical), Markdown, self-contained HTML and SARIF 2.1.0. |
| `target` | Resolves user input: folders, archives (zip-slip-safe), repository URLs (git clone) and website URLs. |
| `netguard` | HTTP clients that enforce each capability's host allow-list, optionally block private networks (hosted mode) and record every outbound call. |
| `cache` | Local SQLite result cache (pure Go, no cgo). |
| `builtin` | Capabilities every other capability depends on: `inventory` (Repository Inventory) and `web-snapshot` (Website Snapshot). |
| `standalone` | Helper that gives each analyzer repository its own small binary. |
| `analyzertest` | Test helpers: run a capability through the real pipeline, golden files. |

## Design rules

- **Local-first.** Nothing needs the network unless a capability declares it, and `--offline` guarantees none is used.
- **Declared, enforced network use.** A capability can only reach the hosts listed in its `capability.yaml`.
- **Evidence before opinion.** Findings carry location, rule, confidence and remediation. Scores are computed from findings using a published method (`capybari-docs/methodology/scoring.md`) and always run 0 = worst to 100 = best.
- **Adding a capability is cheap.** Implement `Analyzer`, write `capability.yaml`, register it in the CLI. There is no new product to build.

## Minimal analyzer

```go
//go:embed capability.yaml
var capabilityYAML []byte

type Analyzer struct{}

func (*Analyzer) Capability() analyzer.Capability { return analyzer.MustParseCapability(capabilityYAML) }

func (*Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	var inv facts.Inventory
	in.Evidence.Get(facts.KeyInventory, &inv)
	// ... inspect files under in.Target.Root ...
	return &analyzer.Result{Findings: findings, Summary: "..."}, nil
}
```

Start new analyzers from [`capybari-analyzer-template`](https://github.com/capybari-repo/capybari-analyzer-template).

## Development

```bash
go test -race ./...
```

Pre-release note: `go.mod` points at a sibling `../capybari-schemas` checkout through a `replace` directive until the repositories are tagged.

The reusable CI workflow for analyzer repositories is `.github/workflows/analyzer-ci.yml`.

## License

Apache-2.0
