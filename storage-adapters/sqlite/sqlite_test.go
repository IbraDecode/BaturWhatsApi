package sqlite

import "testing"

// TestNewSQLiteStub mirrors the postgres stub test.
func TestNewSQLiteStub(t *testing.T) {
	if _, err := NewSQLite(":memory:"); err == nil {
		t.Fatal("expected stub error, got nil")
	} else if err != ErrNotImplemented {
		t.Fatalf("unexpected error: %v", err)
	}
}
