package storage

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Postgres{db: db}, nil
}

func (p *Postgres) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

// DB returns underlying *sql.DB (for migrations etc.)
func (p *Postgres) DB() *sql.DB {
	return p.db
}

// Migrate runs DB migrations using the underlying *sql.DB.
// IMPORTANT: this assumes RunMigrations signature is: RunMigrations(db *sql.DB, dir string) error
func (p *Postgres) Migrate(dir string) error {
	return RunMigrations(p.db, dir)
}
