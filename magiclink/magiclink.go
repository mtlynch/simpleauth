package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/mtlynch/simpleauth/v3"
)

const (
	defaultTokenLifetime = 30 * time.Minute
	defaultRateLimit     = 5
	defaultRateWindow    = time.Hour
	randomTokenBytes     = 32
)

// Token identifies a pending magic-link login.
type Token struct {
	value string
}

// Entry is a stored magic-link token.
type Entry struct {
	Token     Token
	UserID    simpleauth.UserID
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store persists magic-link tokens.
type Store interface {
	CreateToken(ctx context.Context, entry Entry) error
	ConsumeToken(
		ctx context.Context,
		token Token,
		now time.Time,
	) (simpleauth.UserID, error)
	CountTokensSince(
		ctx context.Context,
		userID simpleauth.UserID,
		since time.Time,
	) (int, error)
}

// SessionManager creates authenticated browser sessions.
type SessionManager interface {
	CreateSession(context.Context, http.ResponseWriter, simpleauth.User) error
}

// Config controls magic-link authentication.
type Config struct {
	Store          Store
	Users          simpleauth.UserStore
	LinkSender     simpleauth.LoginLinkSender
	SessionManager SessionManager
	ConfirmURL     string
	TokenLifetime  time.Duration
	RateLimit      int
	RateWindow     time.Duration
	Now            func() time.Time
}

// Authenticator issues and confirms magic login links.
type Authenticator struct {
	store          Store
	users          simpleauth.UserStore
	linkSender     simpleauth.LoginLinkSender
	sessionManager SessionManager
	confirmURL     string
	tokenLifetime  time.Duration
	rateLimit      int
	rateWindow     time.Duration
	now            func() time.Time
}

var (
	// ErrInvalidToken indicates that a token is malformed or unknown.
	ErrInvalidToken = errors.New("invalid magic-link token")

	// ErrExpiredToken indicates that a token is past its expiry time.
	ErrExpiredToken = errors.New("magic-link token has expired")

	// ErrUsedToken indicates that a token has already been consumed.
	ErrUsedToken = errors.New("magic-link token has already been used")

	// ErrRateLimitExceeded indicates that a user requested too many links.
	ErrRateLimitExceeded = errors.New("magic-link rate limit exceeded")
)

// NewToken validates and creates a magic-link token.
func NewToken(raw string) (Token, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(decoded) < randomTokenBytes {
		return Token{}, fmt.Errorf(
			"%w: got %d bytes, want at least %d",
			ErrInvalidToken,
			len(decoded),
			randomTokenBytes,
		)
	}
	return Token{value: raw}, nil
}

// String returns the token as a string.
func (t Token) String() string {
	return t.value
}

// New creates a magic-link authenticator.
func New(config Config) Authenticator {
	if config.Store == nil {
		panic("magic-link authenticator requires a store")
	}
	if config.Users == nil {
		panic("magic-link authenticator requires users")
	}
	if config.SessionManager == nil {
		panic("magic-link authenticator requires a session manager")
	}
	if config.Now == nil {
		panic("magic-link authenticator requires a clock")
	}
	tokenLifetime := config.TokenLifetime
	if tokenLifetime == 0 {
		tokenLifetime = defaultTokenLifetime
	}
	rateLimit := config.RateLimit
	if rateLimit == 0 {
		rateLimit = defaultRateLimit
	}
	rateWindow := config.RateWindow
	if rateWindow == 0 {
		rateWindow = defaultRateWindow
	}
	return Authenticator{
		store:          config.Store,
		users:          config.Users,
		linkSender:     config.LinkSender,
		sessionManager: config.SessionManager,
		confirmURL:     config.ConfirmURL,
		tokenLifetime:  tokenLifetime,
		rateLimit:      rateLimit,
		rateWindow:     rateWindow,
		now:            config.Now,
	}
}

// RequestLoginLink creates a login link and sends it to the matched user.
func (a Authenticator) RequestLoginLink(
	ctx context.Context,
	email string,
) error {
	if a.linkSender == nil {
		return errors.New("magic-link authenticator requires a link sender")
	}
	loginLink, user, err := a.createLoginLink(ctx, email)
	if err != nil {
		return err
	}
	if user.ID.String() == "" {
		return nil
	}
	if err := a.linkSender.SendLoginLink(ctx, user, loginLink); err != nil {
		return fmt.Errorf("send login link: %w", err)
	}
	return nil
}

// CreateLoginLink creates a login link and returns it without sending email.
func (a Authenticator) CreateLoginLink(
	ctx context.Context,
	email string,
) (string, error) {
	loginLink, user, err := a.createLoginLink(ctx, email)
	if err != nil {
		return "", err
	}
	if user.ID.String() == "" {
		return "", simpleauth.ErrUserNotFound
	}
	return loginLink, nil
}

// ConfirmLogin consumes a token and creates a browser session.
func (a Authenticator) ConfirmLogin(
	ctx context.Context,
	w http.ResponseWriter,
	token Token,
) error {
	userID, err := a.store.ConsumeToken(ctx, token, a.now())
	if err != nil {
		return err
	}
	user, err := a.users.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("find user by ID: %w", err)
	}
	if err := a.sessionManager.CreateSession(ctx, w, user); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (a Authenticator) createLoginLink(
	ctx context.Context,
	email string,
) (string, simpleauth.User, error) {
	user, err := a.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, simpleauth.ErrUserNotFound) {
			return "", simpleauth.User{}, nil
		}
		return "", simpleauth.User{}, fmt.Errorf("find user by email: %w", err)
	}
	if err := user.Validate(); err != nil {
		return "", simpleauth.User{}, err
	}
	count, err := a.store.CountTokensSince(
		ctx,
		user.ID,
		a.now().Add(-1*a.rateWindow),
	)
	if err != nil {
		return "", simpleauth.User{}, fmt.Errorf("count login tokens: %w", err)
	}
	if count >= a.rateLimit {
		return "", simpleauth.User{}, ErrRateLimitExceeded
	}

	token, err := newToken()
	if err != nil {
		return "", simpleauth.User{}, err
	}
	now := a.now()
	if err := a.store.CreateToken(ctx, Entry{
		Token:     token,
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(a.tokenLifetime),
	}); err != nil {
		return "", simpleauth.User{}, fmt.Errorf("create login token: %w", err)
	}
	return a.confirmURLWithToken(token), user, nil
}

func (a Authenticator) confirmURLWithToken(token Token) string {
	u, err := url.Parse(a.confirmURL)
	if err != nil {
		panic(fmt.Sprintf("parse confirm URL: %v", err))
	}
	values := u.Query()
	values.Set("token", token.String())
	u.RawQuery = values.Encode()
	return u.String()
}

func newToken() (Token, error) {
	b := make([]byte, randomTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, fmt.Errorf("generate magic-link token: %w", err)
	}
	return Token{value: base64.RawURLEncoding.EncodeToString(b)}, nil
}
