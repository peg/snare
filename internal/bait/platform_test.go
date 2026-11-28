package bait

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withGOOS(t *testing.T, value string) {
	t.Helper()
	prev := goos
	goos = value
	t.Cleanup(func() { goos = prev })
}

func TestWindowsTemplatesAvoidShell(t *testing.T) {
	withGOOS(t, "windows")
	t.Setenv("SystemRoot", `C:\Windows`)
	params := Params{
		TokenID:     "test-abc123",
		CallbackURL: "https://snare.sh/c/test-abc123",
		ProfileName: "prod-admin",
		FakeKeyID:   "AKIAABCDEFGHIJKLMNOP",
		FakeSecret:  "123456789012",
		FakeToken:   "abc+/def",
	}
	want := map[Type]string{
		TypeSSH:     "    ProxyCommand curl.exe -s -o NUL --max-time 5 https://snare.sh/c/test-abc123/ssh\n",
		TypeAWSProc: `credential_process = C:\Windows\System32\curl.exe -s -o NUL --max-time 5 https://snare.sh/c/test-abc123` + "\n",
	}
	for typ, line := range want {
		placed, err := Plant(typ, params, filepath.Join(t.TempDir(), "config"), true, true)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if !strings.Contains(placed.Content, line) {
			t.Errorf("%s: missing %q in\n%s", typ, line, placed.Content)
		}
		if strings.Contains(placed.Content, "sh -c") || strings.ContainsAny(placed.Content, "\"&|<>^%") {
			t.Errorf("%s: Windows template contains shell or cmd.exe metacharacters:\n%s", typ, placed.Content)
		}
	}
}

func TestNonWindowsKeepsShellTemplates(t *testing.T) {
	withGOOS(t, "linux")
	tmpl, _ := templateFor(TypeAWSProc)
	if tmpl != templates[TypeAWSProc] {
		t.Fatal("linux must use the shell awsproc template")
	}
}

func TestWindowsDefaultPaths(t *testing.T) {
	withGOOS(t, "windows")
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "AppData", "Roaming"))
	t.Setenv("AppData", filepath.Join(tmp, "AppData", "Roaming"))
	home, _ := os.UserHomeDir()
	appData, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	want := map[Type]string{
		TypeGCP:       filepath.Join(appData, "gcloud", "sa-prod-backup.json"),
		TypePyPI:      filepath.Join(appData, "pip", "pip.ini"),
		TypeTerraform: filepath.Join(appData, "terraform.rc"),
		TypeAWSProc:   filepath.Join(home, ".aws", "config"),
	}
	for typ, path := range want {
		got, err := DefaultPaths(typ)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if len(got) != 1 || got[0] != path {
			t.Errorf("%s: got %v, want %s", typ, got, path)
		}
	}
}

func TestPlantRejectsUnsafeCallbackURL(t *testing.T) {
	for _, url := range []string{
		"https://snare.sh/c/x'$(id)",
		"https://snare.sh/c/x&calc",
		"https://snare.sh/c/x%PATH%",
		"https://snare.sh/c/x?a=b",
		"file:///etc/passwd",
	} {
		params := Params{TokenID: "x", CallbackURL: url, ProfileName: "p"}
		if _, err := Plant(TypeSSH, params, filepath.Join(t.TempDir(), "config"), true, true); err == nil {
			t.Errorf("accepted unsafe callback URL %q", url)
		}
	}
}
