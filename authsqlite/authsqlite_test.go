package authsqlite_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/mtlynch/simpleauth/v3"
	"github.com/mtlynch/simpleauth/v3/authsqlite"
	"github.com/mtlynch/simpleauth/v3/magiclink"
	"github.com/mtlynch/simpleauth/v3/sessions"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

var fixedNow = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

func TestSessionStore(t *testing.T) {
	db := newDB(t)
	createSessionTables(t, db)
	store, err := authsqlite.NewSessionStore(db)
	if err != nil {
		t.Fatalf("creating session store: %v", err)
	}
	sessionID := mustSessionID(t)
	userID := mustUserID(t)
	if err := store.CreateSession(context.Background(), sessions.Session{
		ID:          sessionID,
		UserID:      userID,
		SessionData: []byte(`{"userId":123}`),
		CreatedAt:   fixedNow,
	}); err != nil {
		t.Fatalf("creating session: %v", err)
	}

	session, err := store.ReadSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("reading session: %v", err)
	}
	if got, want := session.UserID, userID; got != want {
		t.Errorf("session.UserID=%v, want %v", got, want)
	}
	if got, want := string(session.SessionData), `{"userId":123}`; got != want {
		t.Errorf("session.SessionData=%v, want %v", got, want)
	}

	if err := store.DeleteSession(context.Background(), sessionID); err != nil {
		t.Fatalf("deleting session: %v", err)
	}
	_, err = store.ReadSession(context.Background(), sessionID)
	if got, want := err, sessions.ErrNoSessionFound; got != want {
		t.Errorf("err=%v, want %v", got, want)
	}
}

func TestMagicLinkStore(t *testing.T) {
	db := newDB(t)
	createMagicLinkTables(t, db)
	store, err := authsqlite.NewMagicLinkStore(db)
	if err != nil {
		t.Fatalf("creating magic-link store: %v", err)
	}
	userID := mustUserID(t)
	token := mustToken(t)
	if err := store.CreateToken(context.Background(), magiclink.Entry{
		Token:     token,
		UserID:    userID,
		CreatedAt: fixedNow,
		ExpiresAt: fixedNow.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("creating token: %v", err)
	}

	count, err := store.CountTokensSince(
		context.Background(),
		userID,
		fixedNow.Add(-1*time.Hour),
	)
	if err != nil {
		t.Fatalf("counting tokens: %v", err)
	}
	if got, want := count, 1; got != want {
		t.Errorf("count=%v, want %v", got, want)
	}

	consumedUserID, err := store.ConsumeToken(context.Background(), token, fixedNow)
	if err != nil {
		t.Fatalf("consuming token: %v", err)
	}
	if got, want := consumedUserID, userID; got != want {
		t.Errorf("consumedUserID=%v, want %v", got, want)
	}

	_, err = store.ConsumeToken(context.Background(), token, fixedNow)
	if got, want := err, magiclink.ErrUsedToken; got != want {
		t.Errorf("err=%v, want %v", got, want)
	}
}

func TestSessionStoreConstructorDoesNotCreateTables(t *testing.T) {
	db := newDB(t)
	if _, err := authsqlite.NewSessionStore(db); err != nil {
		t.Fatalf("creating session store: %v", err)
	}

	if got, want := tableExists(t, db, "sessions"), false; got != want {
		t.Errorf("tableExists=%v, want %v", got, want)
	}
}

func TestMagicLinkStoreConstructorDoesNotCreateTables(t *testing.T) {
	db := newDB(t)
	if _, err := authsqlite.NewMagicLinkStore(db); err != nil {
		t.Fatalf("creating magic-link store: %v", err)
	}

	if got, want := tableExists(t, db, "login_tokens"), false; got != want {
		t.Errorf("tableExists=%v, want %v", got, want)
	}
}

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := driver.Open(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory SQLite DB: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("closing DB: %v", err)
		}
	})
	return db
}

func createSessionTables(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE sessions (
			session_id TEXT PRIMARY KEY CHECK (session_id != ''),
			user_id TEXT NOT NULL CHECK (user_id != ''),
			session_data TEXT NOT NULL,
			created_at INTEGER NOT NULL
		) STRICT;
		CREATE INDEX sessions_user_id_idx
			ON sessions (user_id);
	`); err != nil {
		t.Fatalf("creating session tables: %v", err)
	}
}

func createMagicLinkTables(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE login_tokens (
			token TEXT PRIMARY KEY CHECK (token != ''),
			user_id TEXT NOT NULL CHECK (user_id != ''),
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			consumed_at INTEGER
		) STRICT;
		CREATE INDEX login_tokens_user_id_created_at_idx
			ON login_tokens (user_id, created_at);
	`); err != nil {
		t.Fatalf("creating magic-link tables: %v", err)
	}
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM sqlite_master
		WHERE type = 'table'
			AND name = :table`,
		sql.Named("table", table),
	).Scan(&count); err != nil {
		t.Fatalf("checking table existence: %v", err)
	}
	return count > 0
}

func mustSessionID(t *testing.T) sessions.ID {
	t.Helper()
	id, err := sessions.NewID(base64.RawURLEncoding.EncodeToString([]byte(
		"12345678901234567890123456789012",
	)))
	if err != nil {
		t.Fatalf("creating session ID: %v", err)
	}
	return id
}

func mustToken(t *testing.T) magiclink.Token {
	t.Helper()
	token, err := magiclink.NewToken(base64.RawURLEncoding.EncodeToString([]byte(
		"12345678901234567890123456789012",
	)))
	if err != nil {
		t.Fatalf("creating token: %v", err)
	}
	return token
}

func mustUserID(t *testing.T) simpleauth.UserID {
	t.Helper()
	userID, err := simpleauth.NewUserID("123")
	if err != nil {
		t.Fatalf("creating user ID: %v", err)
	}
	return userID
}
