// Package version provides non-secret build metadata, without requiring Git.
package version

import (
	"runtime"
	"ssmh/internal/logging"
)

// Version is supplied using -ldflags -X ssmh/internal/version.Version=VERSION.
var Version = "dev"

// String formats the version and toolchain without developer filesystem paths.
func String() string {
	return "ssmh " + logging.SafeText(Version) + " (" + runtime.Version() + "; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
