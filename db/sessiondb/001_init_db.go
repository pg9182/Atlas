package sessiondb

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

func init() {
	migrate(up001, down001)
}

func up001(ctx context.Context, tx *sqlx.Tx) error {
	if _, err := tx.ExecContext(ctx, strings.ReplaceAll(`
		CREATE TABLE session (
			session_id INTEGER PRIMARY KEY AUTOINCREMENT, -- internal sequential unique session id (must never be duplicated even after deletion)
			session_token TEXT, -- opaque session token for clients
			session_created INTEGER, -- unix timestamp
			session_used INTEGER, -- unix timestamp
			session_data TEXT -- json blob containing info from when the session was created
		) STRICT;

		CREATE TABLE player_session (
			player_uid INTEGER PRIMARY KEY,
			player_session_created INTEGER, -- unix timestamp
			session_id INTEGER -- active session for the player (not a fk since it may be deleted)
		) STRICT;

		CREATE TABLE server_session (
			server_addr TEXT PRIMARY KEY, -- canonical non-expanded ip:port
			server_session_created INTEGER, -- unix timestamp
			session_id INTEGER -- active session for the server (not a fk since it may be deleted)
		) STRICT;

		CREATE TABLE player_username (
			player_uid INTEGER PRIMARY KEY,
			player_username TEXT -- last known player username
		) STRICT;
	`, `
		`, "\n")); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}
	if _, err := tx.ExecContext(ctx, strings.ReplaceAll(`
		CREATE INDEX session_token_idx ON session (session_token); -- used for lookup
		CREATE INDEX session_used_idx ON session (session_used); -- used for expiration
		CREATE INDEX player_session_created_idx ON player_session (player_session_created); -- used for expiration
		CREATE INDEX server_session_created_idx ON server_session (server_session_created); -- used for expiration
		CREATE INDEX player_username_idx ON player_username (player_username); -- used for reverse lookup
	`, `
		`, "\n")); err != nil {
		return fmt.Errorf("create indexes: %w", err)
	}
	return nil
}

func down001(ctx context.Context, tx *sqlx.Tx) error {
	if _, err := tx.ExecContext(ctx, `
		DROP INDEX session_token_idx;
		DROP INDEX session_used_idx;
		DROP INDEX player_session_created_idx;
		DROP INDEX server_session_created_idx;
		DROP INDEX player_username_idx;
	`); err != nil {
		return fmt.Errorf("drop indexes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DROP TABLE session;
		DROP TABLE player_session;
		DROP TABLE server_session;
		DROP TABLE player_username;
	`); err != nil {
		return fmt.Errorf("drop tables: %w", err)
	}
	return nil
}
