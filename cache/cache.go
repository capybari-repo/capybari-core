// Package cache provides the local SQLite-backed result cache used by the
// engine to reuse unchanged evidence across repeated scans (pure Go, no cgo).
package cache

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/capybari/capybari-core/engine"

	_ "modernc.org/sqlite"
)

// SQLite is an engine.Cache stored in a single SQLite file.
type SQLite struct {
	db  *sql.DB
	ttl time.Duration
}

// DefaultPath returns the per-user cache location.
func DefaultPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "capybari", "cache.db"), nil
}

// Open opens (creating if needed) a cache database. Entries older than ttl
// are ignored and pruned; ttl <= 0 means 30 days.
func Open(path string, ttl time.Duration) (*SQLite, error) {
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS results (
		key TEXT PRIMARY KEY,
		created_at INTEGER NOT NULL,
		record BLOB NOT NULL)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("init cache: %w", err)
	}
	c := &SQLite{db: db, ttl: ttl}
	_, _ = db.Exec(`DELETE FROM results WHERE created_at < ?`, time.Now().Add(-ttl).Unix())
	return c, nil
}

// Get implements engine.Cache.
func (c *SQLite) Get(key string) (*engine.RunRecord, bool) {
	var blob []byte
	var created int64
	err := c.db.QueryRow(`SELECT record, created_at FROM results WHERE key = ?`, key).Scan(&blob, &created)
	if err != nil || time.Since(time.Unix(created, 0)) > c.ttl {
		return nil, false
	}
	var rec engine.RunRecord
	if json.Unmarshal(blob, &rec) != nil {
		return nil, false
	}
	return &rec, true
}

// Put implements engine.Cache.
func (c *SQLite) Put(key string, rec *engine.RunRecord) error {
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = c.db.Exec(`INSERT OR REPLACE INTO results (key, created_at, record) VALUES (?, ?, ?)`, key, time.Now().Unix(), blob)
	return err
}

// Clear removes every entry.
func (c *SQLite) Clear() error {
	_, err := c.db.Exec(`DELETE FROM results`)
	return err
}

// Close closes the database.
func (c *SQLite) Close() error { return c.db.Close() }
