package authsqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mtlynch/simpleauth/v3"
	"github.com/mtlynch/simpleauth/v3/sessions"
)

// SessionStore stores sessions in SQLite.
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore returns a SQLite-backed session store.
func NewSessionStore(db *sql.DB) (SessionStore, error) {
	if db == nil {
		return SessionStore{}, errors.New("session store requires a database")
	}
	return SessionStore{db: db}, nil
}

// CreateSession stores a new session.
func (s SessionStore) CreateSession(
	ctx context.Context,
	session sessions.Session,
) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (session_id, user_id, session_data, created_at)
		VALUES (:session_id, :user_id, :session_data, :created_at)`,
		sql.Named("session_id", session.ID.String()),
		sql.Named("user_id", session.UserID.String()),
		sql.Named("session_data", string(session.SessionData)),
		sql.Named("created_at", session.CreatedAt.Unix()),
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// ReadSession reads a session by ID.
func (s SessionStore) ReadSession(
	ctx context.Context,
	id sessions.ID,
) (sessions.Session, error) {
	var userIDRaw string
	var sessionData string
	var createdAtUnix int64
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, session_data, created_at
		FROM sessions
		WHERE session_id = :session_id`,
		sql.Named("session_id", id.String()),
	).Scan(&userIDRaw, &sessionData, &createdAtUnix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sessions.Session{}, sessions.ErrNoSessionFound
		}
		return sessions.Session{}, fmt.Errorf("read session: %w", err)
	}
	userID, err := simpleauth.NewUserID(userIDRaw)
	if err != nil {
		return sessions.Session{}, fmt.Errorf("parse user ID: %w", err)
	}
	return sessions.Session{
		ID:          id,
		UserID:      userID,
		SessionData: []byte(sessionData),
		CreatedAt:   time.Unix(createdAtUnix, 0),
	}, nil
}

// DeleteSession deletes a session by ID.
func (s SessionStore) DeleteSession(
	ctx context.Context,
	id sessions.ID,
) error {
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM sessions
		WHERE session_id = :session_id`,
		sql.Named("session_id", id.String()),
	); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
