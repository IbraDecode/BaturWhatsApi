package postgres

import "testing"

// TestNewPostgresStub verifies the stub returns ErrNotImplemented.
// The real implementation must remove this test (or invert its
// semantics) once a driver is chosen.
func TestNewPostgresStub(t *testing.T) {
	if _, err := NewPostgres("postgres://localhost/x"); err == nil {
		t.Fatal("expected stub error, got nil")
	} else if err != ErrNotImplemented {
		t.Fatalf("unexpected error: %v", err)
	}
}
