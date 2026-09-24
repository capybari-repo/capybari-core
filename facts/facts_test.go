package facts

import "testing"

func TestPathContext(t *testing.T) {
	for p, want := range map[string]Context{
		"lib/app.js":                       ContextProduction,
		"examples/celery/requirements.txt": ContextExample,
		"testdata/certificate/key.pem":     ContextTest,
		"context_test.go":                  ContextTest,
		"src/app.spec.ts":                  ContextTest,
		"docs/config.rst":                  ContextDocs,
		"tests/test_apps/.env":             ContextTest,
		"packages/demo/src/index.ts":       ContextExample,
		"src/testing/helpers.go":           ContextTest,
		"requirements.txt":                 ContextProduction,
	} {
		if got := PathContext(p); got != want {
			t.Errorf("%s: %s, want %s", p, got, want)
		}
	}
}
