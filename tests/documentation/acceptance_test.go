package doccheck

import (
	"flag"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"ssmh/internal/cli"
	"ssmh/internal/config"
)

// This guards audit inventory coverage only. It cannot establish that a row's
// assessment is correct, that its evidence is sufficient, or that AWS works.
func TestAcceptanceAuditInventory(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	prompt := read("../../PROMPT.md")
	audit := read("../../docs/acceptance.md")
	sections := regexp.MustCompile(`(?m)^# ([0-9]+)\. `).FindAllStringSubmatch(prompt, -1)
	if len(sections) == 0 {
		t.Fatal("prompt section inventory is empty; review document format")
	}
	for _, section := range sections {
		row := regexp.MustCompile(`(?m)^\| ` + section[1] + `[AB]?: `)
		if !row.MatchString(audit) {
			t.Errorf("audit omits prompt section %s", section[1])
		}
	}
	_, criteria, found := strings.Cut(prompt, "# 25. Acceptance Criteria\n")
	criteria, _, closed := strings.Cut(criteria, "\n# 26.")
	if !found || !closed {
		t.Fatal("cannot locate prompt acceptance criteria")
	}
	_, table, found := strings.Cut(audit, "## Numbered acceptance criteria (PROMPT section 25)\n")
	table, _, closed = strings.Cut(table, "\n## Validation")
	if !found || !closed {
		t.Fatal("cannot locate audit acceptance table")
	}
	items := regexp.MustCompile(`(?m)^([0-9]+)\. `).FindAllStringSubmatch(criteria, -1)
	if len(items) == 0 {
		t.Fatal("prompt acceptance inventory is empty")
	}
	for _, item := range items {
		if count := strings.Count(table, "\n| "+item[1]+" | "); count != 1 {
			t.Errorf("acceptance criterion %s has %d audit rows, want one", item[1], count)
		}
	}
	_, options, found := strings.Cut(audit, "## All named CLI options\n")
	options, _, closed = strings.Cut(options, "\n## Numbered acceptance")
	if !found || !closed {
		t.Fatal("cannot locate audit flag inventory")
	}
	var opts config.Options
	cli.Flags(&opts, io.Discard).VisitAll(func(f *flag.Flag) {
		prefix := "--"
		if len(f.Name) == 1 {
			prefix = "-"
		}
		if !regexp.MustCompile(regexp.QuoteMeta(prefix+f.Name) + "(?:[/`, ]|$)").MatchString(options) {
			t.Errorf("audit flag inventory omits %s%s", prefix, f.Name)
		}
	})
}
