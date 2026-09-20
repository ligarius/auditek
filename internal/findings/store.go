package findings

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Finding struct {
	ID        int64
	ScanID    string
	RuleID    string
	RuleName  string
	Target    string
	Severity  string
	CVE       string
	Impact    string
	Evidence  string
	Timestamp time.Time
}

type Scan struct {
	ID        string
	Type      string
	Target    string
	StartedAt time.Time
	Stealth   bool
}

type Store struct {
	db *sql.DB
}

func Open() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".auditek")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "auditek.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		target TEXT NOT NULL,
		started_at DATETIME NOT NULL,
		stealth BOOLEAN NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		rule_id TEXT NOT NULL,
		rule_name TEXT NOT NULL,
		target TEXT NOT NULL,
		severity TEXT NOT NULL,
		cve TEXT,
		impact TEXT,
		evidence TEXT,
		timestamp DATETIME NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id)
	);

	CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) SaveScan(scan Scan) error {
	_, err := s.db.Exec(
		`INSERT INTO scans (id, type, target, started_at, stealth) VALUES (?, ?, ?, ?, ?)`,
		scan.ID, scan.Type, scan.Target, scan.StartedAt, scan.Stealth,
	)
	return err
}

func (s *Store) SaveFindings(scanID string, fs []Finding) error {
	if len(fs) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(
		`INSERT INTO findings (scan_id, rule_id, rule_name, target, severity, cve, impact, evidence, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, f := range fs {
		_, err := stmt.Exec(scanID, f.RuleID, f.RuleName, f.Target, f.Severity, f.CVE, f.Impact, f.Evidence, f.Timestamp)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) GetFindingsByScan(scanID string) ([]Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, rule_id, rule_name, target, severity, cve, impact, evidence, timestamp
		 FROM findings WHERE scan_id = ? ORDER BY severity`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.RuleID, &f.RuleName, &f.Target, &f.Severity, &f.CVE, &f.Impact, &f.Evidence, &f.Timestamp); err != nil {
			return nil, err
		}
		results = append(results, f)
	}
	return results, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
