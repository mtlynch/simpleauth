package simpleauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// UserID is the stable user identifier that simpleauth stores in auth
// artifacts.
type UserID struct {
	value string
}

// ErrUserNotFound is returned when no user exists for the requested lookup.
var ErrUserNotFound = errors.New("user not found")

// NewUserID creates a user ID from a caller-owned stable identifier.
func NewUserID(raw string) (UserID, error) {
	if raw == "" {
		return UserID{}, errors.New("user ID must not be empty")
	}
	return UserID{value: raw}, nil
}

// String returns the user ID as a string.
func (id UserID) String() string {
	return id.value
}

// User is the minimal user representation required by simpleauth.
type User struct {
	ID          UserID
	SessionData json.RawMessage
	Email       string
	Name        string
}

// Validate verifies that the user has the fields required for authentication.
func (u User) Validate() error {
	if u.ID.String() == "" {
		return errors.New("user ID must not be empty")
	}
	if u.Email == "" {
		return fmt.Errorf("email must not be empty for user %s", u.ID)
	}
	return nil
}

// UserStore looks up users for authentication.
type UserStore interface {
	FindByEmail(ctx context.Context, email string) (User, error)
	FindByID(ctx context.Context, id UserID) (User, error)
}

// LoginLinkSender sends magic login links to users.
type LoginLinkSender interface {
	SendLoginLink(ctx context.Context, user User, confirmURL string) error
}
