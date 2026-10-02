package resigning

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

const ruleStoreSchema = `
CREATE TABLE IF NOT EXISTS Rules (
	id          TEXT PRIMARY KEY NOT NULL,
	owner       TEXT NOT NULL,
	description TEXT NOT NULL,
	condition   TEXT,
	signWith    TEXT NOT NULL,
	created     INTEGER NOT NULL,
	expires     INTEGER
);
CREATE INDEX IF NOT EXISTS RulesOwner ON Rules(owner);
`

// RuleFilter selects rules. Empty fields match everything.
type RuleFilter struct {
	ID    string
	Owner string
	// SignWith matches rules signing with this private key.
	SignWith string
}

func (f RuleFilter) matches(r *Rule) bool {
	return (f.ID == "" || f.ID == r.ID) &&
		(f.Owner == "" || f.Owner == r.Owner) &&
		(f.SignWith == "" || slices.Contains(r.SignWith, f.SignWith))
}

// RuleStore persists resigning rules in sqlite.
type RuleStore struct {
	db  *sqlx.DB
	now func() time.Time
}

type ruleRow struct {
	ID          string         `db:"id"`
	Owner       string         `db:"owner"`
	Description string         `db:"description"`
	Condition   sql.NullString `db:"condition"`
	SignWith    string         `db:"signWith"`
	Created     int64          `db:"created"`
	Expires     sql.NullInt64  `db:"expires"`
}

// OpenRuleStore opens (creating if needed) the rule database at path.
func OpenRuleStore(path string) (*RuleStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)", path))
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ruleStoreSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("could not open rule store %s: %w", path, err)
	}
	return &RuleStore{db: db, now: time.Now}, nil
}

// SetClock overrides the time source, for testing expiry.
func (s *RuleStore) SetClock(now func() time.Time) {
	s.now = now
}

func (s *RuleStore) Close() error {
	return s.db.Close()
}

// pruneExpired deletes expired rules.
func (s *RuleStore) pruneExpired(tx *sqlx.Tx) error {
	_, err := tx.Exec(`DELETE FROM Rules WHERE expires IS NOT NULL AND expires <= ?`, s.now().UnixMilli())
	return err
}

// Create stores a new rule.
func (s *RuleStore) Create(rule *Rule) error {
	condition := sql.NullString{}
	if rule.Condition != nil {
		encoded, err := json.Marshal(rule.Condition)
		if err != nil {
			return err
		}
		condition = sql.NullString{String: string(encoded), Valid: true}
	}
	signWith, err := json.Marshal(rule.SignWith)
	if err != nil {
		return err
	}
	expires := sql.NullInt64{}
	if rule.Expires != nil {
		expires = sql.NullInt64{Int64: rule.Expires.UnixMilli(), Valid: true}
	}

	tx, err := s.db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.pruneExpired(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO Rules (id, owner, description, condition, signWith, created, expires)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.Owner, rule.Description, condition, string(signWith), rule.Created.UnixMilli(), expires); err != nil {
		return err
	}
	return tx.Commit()
}

func (row *ruleRow) rule() (Rule, error) {
	rule := Rule{
		ID:          row.ID,
		Owner:       row.Owner,
		Description: row.Description,
		Created:     time.UnixMilli(row.Created),
	}
	if row.Condition.Valid {
		rule.Condition = new(Condition)
		if err := json.Unmarshal([]byte(row.Condition.String), rule.Condition); err != nil {
			return rule, fmt.Errorf("corrupt condition for rule %s: %w", row.ID, err)
		}
	}
	if err := json.Unmarshal([]byte(row.SignWith), &rule.SignWith); err != nil {
		return rule, fmt.Errorf("corrupt keys for rule %s: %w", row.ID, err)
	}
	if row.Expires.Valid {
		expires := time.UnixMilli(row.Expires.Int64)
		rule.Expires = &expires
	}
	return rule, nil
}

func (s *RuleStore) list(q sqlx.Queryer, filter RuleFilter) ([]Rule, error) {
	rows := []ruleRow{}
	query := `SELECT * FROM Rules WHERE (expires IS NULL OR expires > ?)`
	args := []any{s.now().UnixMilli()}
	if filter.ID != "" {
		query += ` AND id = ?`
		args = append(args, filter.ID)
	}
	if filter.Owner != "" {
		query += ` AND owner = ?`
		args = append(args, filter.Owner)
	}
	if err := sqlx.Select(q, &rows, query+` ORDER BY created, id`, args...); err != nil {
		return nil, err
	}
	rules := []Rule{}
	for _, row := range rows {
		rule, err := row.rule()
		if err != nil {
			return nil, err
		}
		if filter.matches(&rule) {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// List returns the unexpired rules matching filter, oldest first.
func (s *RuleStore) List(filter RuleFilter) ([]Rule, error) {
	return s.list(s.db, filter)
}

// Get returns an unexpired rule by ID.
func (s *RuleStore) Get(id string) (*Rule, error) {
	rules, err := s.List(RuleFilter{ID: id})
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	return &rules[0], nil
}

// Delete removes the rules matching filter (and any expired rules), returning the
// unexpired rules deleted.
func (s *RuleStore) Delete(filter RuleFilter) ([]Rule, error) {
	tx, err := s.db.Beginx()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rules, err := s.list(tx, filter)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if _, err := tx.Exec(`DELETE FROM Rules WHERE id = ?`, rule.ID); err != nil {
			return nil, err
		}
	}
	if err := s.pruneExpired(tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return rules, nil
}
