package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This checks the simple inline file links used by repository guides, not all
// CommonMark syntax, heading anchors, external websites or live AWS behavior.
func TestGuideLocalFileLinks(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(root, "README.md"), filepath.Join(root, "TODO.md")}
	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			files = append(files, filepath.Join(root, "docs", entry.Name()))
		}
	}
	links := regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range links.FindAllSubmatch(content, -1) {
			target := strings.Trim(string(match[1]), "<>")
			if strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "#") {
				continue
			}
			target, _, _ = strings.Cut(target, "#")
			if target == "" || filepath.IsAbs(target) {
				t.Errorf("%s has invalid repository file link", file)
				continue
			}
			resolved := filepath.Join(filepath.Dir(file), target)
			resolved, err = filepath.EvalSymlinks(resolved)
			if err != nil {
				t.Errorf("%s links to missing target %s", file, target)
				continue
			}
			relative, err := filepath.Rel(root, resolved)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				t.Errorf("%s links outside the repository", file)
				continue
			}
			info, err := os.Stat(resolved)
			if err != nil || !info.Mode().IsRegular() {
				t.Errorf("%s links to missing/non-file target %s", file, target)
			}
		}
	}
}
