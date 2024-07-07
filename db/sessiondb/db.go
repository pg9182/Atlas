// Package sessiondb implements sqlite3 database storage for api2 sessions.
package sessiondb

import (
	"net/url"

	"github.com/jmoiron/sqlx"
)

// DB stores player data in a sqlite3 database.
type DB struct {
	x *sqlx.DB
}

// Open opens a DB from the provided sqlite3 uri.
func Open(name string) (*DB, error) {
	x, err := sqlx.Connect("sqlite3", (&url.URL{
		Path: name,
		RawQuery: (url.Values{
			"_journal":      {"WAL"},
			"_synchronous":  {"NORMAL"},
			"_busy_timeout": {"3000"},
			"_cache_size":   {"-16000"},
		}).Encode(),
	}).String())
	if err != nil {
		return nil, err
	}
	return &DB{x: x}, nil
}

func (db *DB) Close() error {
	return db.x.Close()
}

// TODO
