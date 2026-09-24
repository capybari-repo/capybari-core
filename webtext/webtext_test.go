package webtext

import "testing"

func TestVisible(t *testing.T) {
	doc := `<html><head><title>T</title><style>p{}</style><script>var x="hidden";</script></head>
<body><h1>Hello &amp; welcome</h1><noscript>enable js</noscript><svg><text>logo</text></svg>
<p>Real   text<br>here</p><template><p>later</p></template></body></html>`
	if got := Visible(doc); got != "T Hello & welcome Real text here" {
		t.Fatalf("Visible = %q", got)
	}
	if Words("a b  c") != 3 {
		t.Fatal("Words")
	}
}
