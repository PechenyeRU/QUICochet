package configmigrate_test

import "os"

// writeTestFile writes content to path with mode 0600 (matches the
// auto-migrator's default) so the auto-migrate path can rewrite it.
func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// readTestFile reads a file as a string, returning empty + error on miss
// so the test can distinguish "file absent" (e.g. .bak not created) from
// "file empty".
func readTestFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
