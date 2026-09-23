// Package version exposes build identity (injected via -ldflags at release).
package version

var (
	// Version is the engine release (overridable via -ldflags
	// -X github.com/ibradecode/baturwhatsapi/internal/version.Version=...).
	Version = "0.1.0"
	// Channel marks the maturity level.
	Channel = "development"
)
