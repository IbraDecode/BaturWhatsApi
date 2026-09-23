// Package version exposes build identity (injected via -ldflags at release).
package version

const (
	// Version is the engine release.
	Version = "0.1.0"
	// Channel marks the maturity level.
	Channel = "development"
)
