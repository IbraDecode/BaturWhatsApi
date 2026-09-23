package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// FileStore persists keys as files under a base directory. Key bytes that
// are not filesystem-safe are hex-escaped; the manifest maps filenames back
// to logical keys so List works exactly.
type FileStore struct {
	mu       sync.RWMutex
	dir      string
	manifest map[string]string // logical key -> filename
}

// NewFileStore opens (creating if needed) a directory-backed store.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("storage: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("storage: create dir: %w", err)
	}
	fs := &FileStore{dir: dir, manifest: map[string]string{}}
	// Rebuild manifest from the index file.
	index, err := os.ReadFile(fs.indexPath())
	if err == nil {
		for _, line := range strings.Split(string(index), "\n") {
			if k, v, ok := strings.Cut(line, "\t"); ok && k != "" && v != "" {
				fs.manifest[k] = v
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return fs, nil
}

func (fs *FileStore) indexPath() string { return filepath.Join(fs.dir, "MANIFEST") }

func encodeKey(key string) string {
	var sb strings.Builder
	for i := 0; i < len(key) && sb.Len() < 180; i++ {
		c := key[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02x", c)
		}
	}
	// Full-key hash suffix: uniqueness plus containment (no traversal).
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s.%s", sb.String(), hex.EncodeToString(sum[:8]))
}

func (fs *FileStore) pathFor(key string) string {
	return filepath.Join(fs.dir, encodeKey(key))
}

// Get implements KV.
func (fs *FileStore) Get(_ context.Context, key string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	data, err := os.ReadFile(fs.pathFor(key))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return data, err
}

// Set implements KV (atomic via rename).
func (fs *FileStore) Set(_ context.Context, key string, value []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	path := fs.pathFor(key)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, value, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	fs.manifest[key] = filepath.Base(path)
	return fs.writeManifestLocked()
}

// Delete implements KV.
func (fs *FileStore) Delete(_ context.Context, key string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	err := os.Remove(fs.pathFor(key))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(fs.manifest, key)
	return fs.writeManifestLocked()
}

// List implements KV.
func (fs *FileStore) List(_ context.Context, prefix string) ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	var out []string
	for k := range fs.manifest {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Close implements KV.
func (fs *FileStore) Close() error { return nil }

func (fs *FileStore) writeManifestLocked() error {
	var sb strings.Builder
	keys := make([]string, 0, len(fs.manifest))
	for k := range fs.manifest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(k + "\t" + fs.manifest[k] + "\n")
	}
	return os.WriteFile(fs.indexPath(), []byte(sb.String()), 0o600)
}
