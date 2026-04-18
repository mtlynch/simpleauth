package authsqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mtlynch/simpleauth/v3"
	"github.com/mtlynch/simpleauth/v3/magiclink"
)

// MagicLinkStore stores magic-link tokens in SQLite.
type MagicLinkStore struct {
	db *sql.DB
}

// NewMagicLinkStore returns a SQLite-backed magic-link store.
func NewMagicLinkStore(db *sql.DB) (MagicLinkStore, error) {
	if db == nil {
		return MagicLinkStore{}, errors.New("magic-link store requires a database")
	}
	return MagicLinkStore{db: db}, nil
}

// CreateToken stores a newly issued magic-link token.
func (s MagicLinkStore) CreateToken(
	ctx context.Context,
	entry magiclink.Entry,
) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO login_tokens (
			token,
			user_id,
			created_at,
			expires_at,
			consumed_at
		)
		VALUES (
			:token,
			:user_id,
			:created_at,
			:expires_at,
			NULL
		)`,
		sql.Named("token", entry.Token.String()),
		sql.Named("user_id", entry.UserID.String()),
		sql.Named("created_at", entry.CreatedAt.Unix()),
		sql.Named("expires_at", entry.ExpiresAt.Unix()),
	)
	if err != nil {
		return fmt.Errorf("insert login token: %w", err)
	}
	return nil
}

// ConsumeToken marks a token consumed and returns the associated user ID.
func (s MagicLinkStore) ConsumeToken(
	ctx context.Context,
	token magiclink.Token,
	now time.Time,
) (simpleauth.UserID, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return simpleauth.UserID{}, fmt.Errorf("begin token transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			panic(fmt.Sprintf("rollback token transaction: %v", err))
		}
	}()

	var userIDRaw string
	var expiresAtUnix int64
	var consumedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT user_id, expires_at, consumed_at
		FROM login_tokens
		WHERE token = :token`,
		sql.Named("token", token.String()),
	).Scan(&userIDRaw, &expiresAtUnix, &consumedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return simpleauth.UserID{}, magiclink.ErrInvalidToken
		}
		return simpleauth.UserID{}, fmt.Errorf("read login token: %w", err)
	}
	if consumedAt.Valid {
		return simpleauth.UserID{}, magiclink.ErrUsedToken
	}
	if now.After(time.Unix(expiresAtUnix, 0)) {
		return simpleauth.UserID{}, magiclink.ErrExpiredToken
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE login_tokens
		SET consumed_at = :consumed_at
		WHERE token = :token
			AND consumed_at IS NULL`,
		sql.Named("consumed_at", now.Unix()),
		sql.Named("token", token.String()),
	)
	if err != nil {
		return simpleauth.UserID{}, fmt.Errorf("consume login token: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return simpleauth.UserID{}, fmt.Errorf("consume login token rows: %w", err)
	}
	if rowsAffected == 0 {
		return simpleauth.UserID{}, magiclink.ErrUsedToken
	}
	if err := tx.Commit(); err != nil {
		return simpleauth.UserID{}, fmt.Errorf("commit token transaction: %w", err)
	}

	userID, err := simpleauth.NewUserID(userIDRaw)
	if err != nil {
		return simpleauth.UserID{}, fmt.Errorf("parse user ID: %w", err)
	}
	return userID, nil
}

// CountTokensSince counts issued tokens for a user inside a time window.
func (s MagicLinkStore) CountTokensSince(
	ctx context.Context,
	userID simpleauth.UserID,
	since time.Time,
) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM login_tokens
		WHERE user_id = :user_id
			AND created_at >= :since`,
		sql.Named("user_id", userID.String()),
		sql.Named("since", since.Unix()),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count login tokens: %w", err)
	}
	return count, nil
}
