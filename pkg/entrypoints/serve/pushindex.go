package serve

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jmoiron/sqlx"
)

// PushIndex records the NAR URLs clients uploaded paths under. Nix caches the narinfo
// it uploads, so a client which pushed a path will later fetch it from its own upload
// URL (nar/<compressed file hash>.nar.<ext>) rather than the URL this server advertises.
type PushIndex interface {
	// Lookup returns the store path and compression of an upload URL.
	Lookup(url string) (storePath string, compression string, found bool, err error)
	Record(url string, storePath string, compression string) error
	Close() error
}

const pushIndexSchema = `
CREATE TABLE IF NOT EXISTS PushedNars (
	url         TEXT PRIMARY KEY NOT NULL,
	storePath   TEXT NOT NULL,
	compression TEXT NOT NULL,
	pushTime    INTEGER NOT NULL
);
`

type pushIndex struct {
	db *sqlx.DB
}

// OpenPushIndex opens the index at path. If writable, it is created if needed; otherwise
// it is opened read-only and must already exist.
func OpenPushIndex(path string, writable bool) (PushIndex, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro", path)
	if writable {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		dsn = fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)", path)
	}
	db, err := sqlx.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if writable {
		_, err = db.Exec(pushIndexSchema)
	} else {
		err = db.Ping()
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("could not open push index %s: %w", path, err)
	}
	return &pushIndex{db: db}, nil
}

func (p *pushIndex) Lookup(url string) (string, string, bool, error) {
	var row struct {
		StorePath   string `db:"storePath"`
		Compression string `db:"compression"`
	}
	err := p.db.Get(&row, `SELECT storePath, compression FROM PushedNars WHERE url = ?`, url)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return row.StorePath, row.Compression, true, nil
}

func (p *pushIndex) Record(url string, storePath string, compression string) error {
	_, err := p.db.Exec(`INSERT OR REPLACE INTO PushedNars (url, storePath, compression, pushTime) VALUES (?, ?, ?, ?)`,
		url, storePath, compression, time.Now().Unix())
	return err
}

func (p *pushIndex) Close() error {
	return p.db.Close()
}
