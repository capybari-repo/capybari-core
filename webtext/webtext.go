// Package webtext extracts what a visitor actually reads from HTML: text
// outside scripts, styles, SVG, templates and hidden inputs, with entities
// decoded and whitespace collapsed. Shared by website capabilities so they
// measure the same text.
package webtext

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

var skip = map[string]bool{"script": true, "style": true, "noscript": true, "svg": true, "template": true, "head": false}

// Visible returns the visible text of an HTML document.
func Visible(doc string) string {
	z := html.NewTokenizer(strings.NewReader(doc))
	var b bytes.Buffer
	depth := 0 // inside skipped elements
	for {
		switch z.Next() {
		case html.ErrorToken:
			return strings.Join(strings.Fields(b.String()), " ")
		case html.StartTagToken:
			name, _ := z.TagName()
			if skip[string(name)] {
				depth++
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if skip[string(name)] && depth > 0 {
				depth--
			}
		case html.TextToken:
			if depth == 0 {
				b.Write(z.Text())
				b.WriteByte(' ')
			}
		}
	}
}

// Words counts whitespace-separated words.
func Words(text string) int { return len(strings.Fields(text)) }
