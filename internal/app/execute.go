// Package app owns the executable's process-level signal and exit boundary.
// Both the root and cmd/ssmh entry points use the same implementation.
package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"ssmh/internal/cli"
)

// Execute runs one invocation using the process arguments and standard streams.
// It returns only after CLI-owned local and AWS cleanup has been attempted.
func Execute() int {
	// Register SIGPIPE too: writes to inherited stdout/stderr must return errors
	// instead of terminating the process before owned-session cleanup can run.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGPIPE)
	defer stop()
	err := cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, "ssmh:", err); writeErr != nil {
			return 1
		}
	}
	return cli.ExitCode(err)
}
