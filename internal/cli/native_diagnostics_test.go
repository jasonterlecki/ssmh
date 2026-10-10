package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/terminal"
)

func TestNativeStateDiagnosticsDebugOnlyAndOwnedCleanup(t *testing.T) {
	for _, mode := range []string{"", "-q", "-v", "--debug"} {
		t.Run(mode, func(t *testing.T) {
			in, out, stderr := cliFiles(t)
			api := &cliAPI{platform: types.PlatformTypeLinux}
			d := cliDeps(api, &cliChannel{}, &idleClient{})
			// Real native Connect rejects this synthetic non-http.Client config
			// before network access. The CLI still owns cleanup of the started session.
			d.connect = production().connect
			d.run = func(context.Context, terminal.Channel, *os.File, *os.File, *os.File) error {
				t.Fatal("failed native setup ran remote operation")
				return nil
			}
			args := []string{"-i", cliTarget, "--reason", "synthetic-secret-reason"}
			if mode != "" {
				args = append(args, mode)
			}
			if err := run(context.Background(), args, in, out, stderr, d); err == nil || api.starts != 1 || api.terminates != 1 || !api.cleanupActive {
				t.Fatal("native failure skipped fresh owned cleanup")
			}
			text := cliText(t, stderr)
			if strings.Contains(text, "native state:") != (mode == "--debug") || cliText(t, out) != "" || strings.Contains(text, "synthetic") || strings.Contains(text, "unit-owned") || strings.Contains(text, "wss:") {
				t.Fatal("native trace ignored opt-in or exposed authentication/payloads")
			}
			if mode == "--debug" {
				if strings.Count(text, "native state: WebSocket opening") != 1 || strings.Count(text, "native state: WebSocket establishment failed") != 1 || strings.Contains(text, "WebSocket authenticated") || !strings.Contains(text, "since_trace_ms=") {
					t.Fatal("failed setup trace mislabeled or repeated")
				}
			}
		})
	}
}
