package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteMigratedConfigDoesNotFollowPredictableSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	original := []byte(`{"mode":"client"}`)
	migrated := []byte(`{"mode":"server"}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, path+".bak"); err != nil {
		t.Fatal(err)
	}

	if err := writeMigratedConfig(path, original, migrated); err != nil {
		t.Fatalf("writeMigratedConfig: %v", err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "unchanged" {
		t.Fatalf("sentinel changed to %q", got)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(migrated) {
		t.Fatalf("config = %q, want %q", got, migrated)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
}
