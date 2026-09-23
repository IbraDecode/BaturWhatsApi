// Package storage defines the engine's persistence abstraction and ships two
// dependency-free backends: an in-memory store (tests, ephemeral mode) and a
// durable file store (single-node deployments). PostgreSQL/SQLite adapters
// plug into the same interface without touching the session engine.
package storage

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
)

// ErrNotFound signals a missing key.
var ErrNotFound = errors.New("storage: key not found")

// KV is the key/value contract used by session persistence, sync
// checkpoints and the supervisor journal. Keys are slash-separated paths;
// backends may organize by prefix but must implement List exactly.
type KV interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte) error
	Delete(ctx context.Context, key string) error
	// List returns all keys with the given prefix, sorted.
	List(ctx context.Context, prefix string) ([]string, error)
	Close() error
}

// Memory is a goroutine-safe in-memory KV.
type Memory struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemory creates an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{data: map[string][]byte{}}
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Get implements KV.
func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[key]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneBytes(v), nil
}

// Set implements KV.
func (m *Memory) Set(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = cloneBytes(value)
	return nil
}

// Delete implements KV (idempotent).
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// List implements KV.
func (m *Memory) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Close implements KV.
func (m *Memory) Close() error { return nil }

// Keys returns every key (diagnostics helper).
func (m *Memory) Keys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.data))
	for k := range m.data {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
