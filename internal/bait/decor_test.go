package bait

import (
	"bytes"
	"strings"
	"testing"
)

func TestTemplatesCarryNoFixedGiveaways(t *testing.T) {
	for _, osName := range []string{"linux", "windows"} {
		withGOOS(t, osName)
		for bt := range templates {
			tmpl, _ := templateFor(bt)
			for i := 0; i < 20; i++ {
				p := Params{TokenID: "tok", CallbackURL: "https://edge.example.net/c/tok", ProfileName: "prod-admin", Decor: NewDecor(bt, "prod-admin")}
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, p); err != nil {
					t.Fatalf("%s/%s: %v", osName, bt, err)
				}
				out := strings.ToLower(buf.String())
				for _, bad := range []string{"snare", "insecure-skip-tls-verify", "stricthostkeychecking", `"description"`, "{name}", "<no value>", "acme", "contoso", "initech"} {
					if strings.Contains(out, bad) {
						t.Fatalf("%s/%s contains %q:\n%s", osName, bt, bad, buf.String())
					}
				}
			}
		}
	}
}

func TestDecorVaries(t *testing.T) {
	seen := map[Decor]bool{}
	for i := 0; i < 50; i++ {
		seen[NewDecor(TypeSSH, "bastion-prod")] = true
	}
	if len(seen) < 3 {
		t.Fatalf("NewDecor produced %d distinct values in 50 draws", len(seen))
	}
	if d := NewDecor(TypeGeneric, ""); strings.Contains(d.Comment, "  ") {
		t.Fatalf("empty name left a gap: %q", d.Comment)
	}
}
