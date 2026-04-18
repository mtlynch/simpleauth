package sessions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/mtlynch/simpleauth/v3"
)

const (
	defaultCookieName = "token"
	defaultCookiePath = "/"
	randomIDBytes     = 32
)

type contextKey struct{}

// ID identifies a server-side session.
type ID struct {
	value string
}

// Session holds the auth session that simpleauth stores and loads.
type Session struct {
	ID          ID
	UserID      simpleauth.UserID
	SessionData json.RawMessage
	CreatedAt   time.Time
}

// Store persists server-side sessions.
type Store interface {
	CreateSession(ctx context.Context, session Session) error
	ReadSession(ctx context.Context, id ID) (Session, error)
	DeleteSession(ctx context.Context, id ID) error
}

// Config controls session manager behavior.
type Config struct {
	Store      Store
	CookieName string
	RequireTLS bool
	Now        func() time.Time
}

// Manager creates, loads, and ends HTTP sessions.
type Manager struct {
	store      Store
	cookieName string
	requireTLS bool
	now        func() time.Time
}

var (
	// ErrInvalidID indicates that a session ID is malformed.
	ErrInvalidID = errors.New("invalid session ID")

	// ErrNoSessionFound indicates that no active session is present.
	ErrNoSessionFound = errors.New("no active session in request context")
)

// NewID validates and creates a session ID.
func NewID(raw string) (ID, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return ID{}, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	if len(decoded) < randomIDBytes {
		return ID{}, fmt.Errorf(
			"%w: got %d bytes, want at least %d",
			ErrInvalidID,
			len(decoded),
			randomIDBytes,
		)
	}
	return ID{value: raw}, nil
}

// String returns the session ID as a string.
func (id ID) String() string {
	return id.value
}

// NewManager creates a session manager.
func NewManager(config Config) Manager {
	if config.Store == nil {
		panic("session manager requires a store")
	}
	if config.Now == nil {
		panic("session manager requires a clock")
	}
	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = defaultCookieName
	}
	return Manager{
		store:      config.Store,
		cookieName: cookieName,
		requireTLS: config.RequireTLS,
		now:        config.Now,
	}
}

// CreateSession creates a new session for user and sets its browser cookie.
func (m Manager) CreateSession(
	ctx context.Context,
	w http.ResponseWriter,
	user simpleauth.User,
) error {
	if err := user.Validate(); err != nil {
		return err
	}
	id, err := newID()
	if err != nil {
		return err
	}
	session := Session{
		ID:          id,
		UserID:      user.ID,
		SessionData: user.SessionData,
		CreatedAt:   m.now(),
	}
	if err := m.store.CreateSession(ctx, session); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	http.SetCookie(w, m.cookie(id))
	return nil
}

// SessionFromContext retrieves the session that middleware loaded.
func SessionFromContext(ctx context.Context) (Session, error) {
	if sess, ok := ctx.Value(contextKey{}).(Session); ok {
		return sess, nil
	}
	return Session{}, ErrNoSessionFound
}

// SessionFromContext retrieves the session that middleware loaded.
func (m Manager) SessionFromContext(ctx context.Context) (Session, error) {
	return SessionFromContext(ctx)
}

// EndSession revokes the loaded session and clears its browser cookie.
func (m Manager) EndSession(ctx context.Context, w http.ResponseWriter) error {
	sess, err := SessionFromContext(ctx)
	if err != nil && !errors.Is(err, ErrNoSessionFound) {
		return err
	}
	if err == nil {
		if err := m.store.DeleteSession(ctx, sess.ID); err != nil {
			return fmt.Errorf("delete session: %w", err)
		}
	}
	http.SetCookie(w, m.expiredCookie())
	return nil
}

// LoadSession loads a session for public routes when a valid cookie exists.
func (m Manager) LoadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := m.sessionFromRequest(r)
		if errors.Is(err, ErrNoSessionFound) {
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(
			r.Context(),
			contextKey{},
			sess,
		)))
	})
}

// RequireSession redirects requests that do not have an active session.
func (m Manager) RequireSession(loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := m.sessionFromRequest(r)
			if errors.Is(err, ErrNoSessionFound) {
				http.Redirect(w, r, loginPath, http.StatusSeeOther)
				return
			}
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(
				r.Context(),
				contextKey{},
				sess,
			)))
		})
	}
}

// WrapRequest loads a session for public routes when a valid cookie exists.
func (m Manager) WrapRequest(next http.Handler) http.Handler {
	return m.LoadSession(next)
}

func (m Manager) sessionFromRequest(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return Session{}, ErrNoSessionFound
		}
		return Session{}, err
	}
	id, err := NewID(cookie.Value)
	if err != nil {
		return Session{}, ErrNoSessionFound
	}
	sess, err := m.store.ReadSession(r.Context(), id)
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

func (m Manager) cookie(id ID) *http.Cookie {
	return &http.Cookie{
		Name:     m.cookieName,
		Value:    id.String(),
		Path:     defaultCookiePath,
		HttpOnly: true,
		Secure:   m.requireTLS,
		SameSite: http.SameSiteLaxMode,
	}
}

func (m Manager) expiredCookie() *http.Cookie {
	return &http.Cookie{
		Name:     m.cookieName,
		Value:    "deleted",
		Path:     defaultCookiePath,
		HttpOnly: true,
		Secure:   m.requireTLS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

func newID() (ID, error) {
	b := make([]byte, randomIDBytes)
	if _, err := rand.Read(b); err != nil {
		return ID{}, fmt.Errorf("generate session ID: %w", err)
	}
	return ID{value: base64.RawURLEncoding.EncodeToString(b)}, nil
}
