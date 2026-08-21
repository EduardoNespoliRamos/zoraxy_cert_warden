package zoraxy_plugin

import "testing"

func TestEscapeCSRFToken(t *testing.T) {
	got := escapeCSRFToken(`"><script>alert(1)</script>`)
	want := "&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
	if got != want {
		t.Fatalf("unexpected escaped token: %q", got)
	}
}
