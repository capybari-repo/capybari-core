// Package lifecycle is the shared, offline end-of-life knowledge base used
// by repository and website technology detection. Data comes from
// https://endoflife.date and vendor pages and is stamped with an as-of date.
package lifecycle

import (
	_ "embed"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed eol.yaml
var eolYAML []byte

// Product is the lifecycle of one product.
type Product struct {
	Source string            `yaml:"source"`
	Kind   string            `yaml:"kind"` // runtime, framework, library
	Note   string            `yaml:"note"`
	Cycles map[string]string `yaml:"cycles"` // release line -> EOL date or "unsupported"
}

// Table is the full data set.
type Table struct {
	AsOf     string             `yaml:"as_of"`
	Products map[string]Product `yaml:"products"`
}

var table = func() Table {
	var t Table
	if err := yaml.Unmarshal(eolYAML, &t); err != nil {
		panic(err)
	}
	return t
}()

// AsOf returns the date the data was last reviewed.
func AsOf() string { return table.AsOf }

// Lookup returns the product lifecycle.
func Lookup(name string) (Product, bool) {
	p, ok := table.Products[name]
	return p, ok
}

// Status is an end-of-life verdict.
type Status struct {
	Product Product
	Cycle   string // release line matched, e.g. "3.7"
	Date    string // EOL date or "unsupported"
	Exact   bool   // version was exact (not a range)
}

var nums = regexp.MustCompile(`\d+`)

// IsRange reports whether a version string is a range rather than a pin.
func IsRange(v string) bool { return strings.ContainsAny(v, "^~<>*| ,") }

// Cycle maps a version to its release line for a product.
func Cycle(product, version string) (key string, exact bool) {
	v := strings.TrimSpace(version)
	if v == "" {
		return "", false
	}
	exact = !IsRange(v)
	if product == ".NET" {
		return strings.ToLower(strings.SplitN(v, ";", 2)[0]), exact
	}
	n := nums.FindAllString(v, 3)
	if len(n) == 0 {
		return "", false
	}
	p := table.Products[product]
	if len(n) >= 2 {
		if _, ok := p.Cycles[n[0]+"."+n[1]]; ok {
			return n[0] + "." + n[1], exact
		}
	}
	return n[0], exact
}

// Check reports whether product@version is end-of-life on the given day.
func Check(product, version string, today time.Time) (*Status, bool) {
	p, ok := table.Products[product]
	if !ok {
		return nil, false
	}
	key, exact := Cycle(product, version)
	if key == "" {
		return nil, false
	}
	date, ok := p.Cycles[key]
	if !ok {
		return nil, false
	}
	if date != "unsupported" {
		d, err := time.Parse("2006-01-02", date)
		if err != nil || !today.After(d) {
			return nil, false
		}
	}
	return &Status{Product: p, Cycle: key, Date: date, Exact: exact}, true
}
