// Package builtin lists the capabilities that ship with capybari-core
// because every other capability depends on the evidence they acquire:
// the repository inventory and the website snapshot.
package builtin

import (
	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/builtin/inventory"
	"github.com/capybari-repo/capybari-core/builtin/websnapshot"
)

// All returns the built-in capabilities.
func All() []analyzer.Analyzer {
	return []analyzer.Analyzer{inventory.New(), websnapshot.New()}
}
