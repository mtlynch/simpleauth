package magiclink_test

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mtlynch/simpleauth/v3"
	"github.com/mtlynch/simpleauth/v3/magiclink"
	"github.com/mtlynch/simpleauth/v3/sessions"
)

var fixedNow = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

type memoryMagicLinkStore struct {
	entries map[string]magiclink.Entry
}

func (s *memoryMagicLinkStore) CreateToken(
	ctx context.Context,
	entry magiclink.Entry,
) error {
	_ = ctx
	s.entries[entry.Token.String()] = entry
	return nil
}

func (s *memoryMagicLinkStore) ConsumeToken(
	ctx context.Context,
	token magiclink.Token,
	now time.Time,
) (simpleauth.UserID, error) {
	_ = ctx
	entry, ok := s.entries[token.String()]
	if !ok {
		return simpleauth.UserID{}, magiclink.ErrInvalidToken
	}
	if now.After(entry.ExpiresAt) {
		return simpleauth.UserID{}, magiclink.ErrExpiredToken
	}
	delete(s.entries, token.String())
	return entry.UserID, nil
}

func (s *memoryMagicLinkStore) CountTokensSince(
	ctx context.Context,
	userID simpleauth.UserID,
	since time.Time,
) (int, error) {
	_ = ctx
	count := 0
	for _, entry := range s.entries {
		if entry.UserID == userID && !entry.CreatedAt.Before(since) {
			count++
		}
	}
	return count, nil
}

type memoryUserStore struct {
	user simpleauth.User
}

func (s memoryUserStore) FindByEmail(
	ctx context.Context,
	email string,
) (simpleauth.User, error) {
	_ = ctx
	if email != s.user.Email {
		return simpleauth.User{}, simpleauth.ErrUserNotFound
	}
	return s.user, nil
}

func (s memoryUserStore) FindByID(
	ctx context.Context,
	id simpleauth.UserID,
) (simpleauth.User, error) {
	_ = ctx
	if id != s.user.ID {
		return simpleauth.User{}, simpleauth.ErrUserNotFound
	}
	return s.user, nil
}

type memorySessionStore struct {
	sessions map[string]sessions.Session
}

func (s *memorySessionStore) CreateSession(
	ctx context.Context,
	session sessions.Session,
) error {
	_ = ctx
	s.sessions[session.ID.String()] = session
	return nil
}

func (s *memorySessionStore) ReadSession(
	ctx context.Context,
	id sessions.ID,
) (sessions.Session, error) {
	_ = ctx
	session, ok := s.sessions[id.String()]
	if !ok {
		return sessions.Session{}, sessions.ErrNoSessionFound
	}
	return session, nil
}

func (s *memorySessionStore) DeleteSession(
	ctx context.Context,
	id sessions.ID,
) error {
	_ = ctx
	delete(s.sessions, id.String())
	return nil
}

func TestCreateLoginLinkAndConfirmLogin(t *testing.T) {
	userID, err := simpleauth.NewUserID("123")
	if err != nil {
		t.Fatalf("creating user ID: %v", err)
	}
	authenticator := magiclink.New(magiclink.Config{
		Store: &memoryMagicLinkStore{
			entries: map[string]magiclink.Entry{},
		},
		Users: memoryUserStore{user: simpleauth.User{
			ID:          userID,
			Email:       "homer@example.com",
			SessionData: []byte(`{"userId":123}`),
		}},
		SessionManager: sessions.NewManager(sessions.Config{
			Store:      &memorySessionStore{sessions: map[string]sessions.Session{}},
			CookieName: "token",
			Now:        func() time.Time { return fixedNow },
		}),
		ConfirmURL:    "/login/confirm",
		TokenLifetime: 30 * time.Minute,
		Now:           func() time.Time { return fixedNow },
	})

	loginLink, err := authenticator.CreateLoginLink(
		context.Background(),
		"homer@example.com",
	)
	if err != nil {
		t.Fatalf("creating login link: %v", err)
	}
	parsedLink, err := url.Parse(loginLink)
	if err != nil {
		t.Fatalf("parsing login link: %v", err)
	}
	token, err := magiclink.NewToken(parsedLink.Query().Get("token"))
	if err != nil {
		t.Fatalf("parsing token: %v", err)
	}
	rec := httptest.NewRecorder()

	if err := authenticator.ConfirmLogin(
		context.Background(),
		rec,
		token,
	); err != nil {
		t.Fatalf("confirming login: %v", err)
	}

	if got, want := len(rec.Result().Cookies()), 1; got != want {
		t.Fatalf("cookies=%v, want %v", got, want)
	}
	if got, want := rec.Result().Cookies()[0].Name, "token"; got != want {
		t.Errorf("cookie name=%v, want %v", got, want)
	}
}

func TestCreateLoginLinkForUnknownUser(t *testing.T) {
	userID, err := simpleauth.NewUserID("123")
	if err != nil {
		t.Fatalf("creating user ID: %v", err)
	}
	authenticator := magiclink.New(magiclink.Config{
		Store: &memoryMagicLinkStore{
			entries: map[string]magiclink.Entry{},
		},
		Users: memoryUserStore{user: simpleauth.User{
			ID:          userID,
			Email:       "homer@example.com",
			SessionData: []byte(`{"userId":123}`),
		}},
		SessionManager: sessions.NewManager(sessions.Config{
			Store:      &memorySessionStore{sessions: map[string]sessions.Session{}},
			CookieName: "token",
			Now:        func() time.Time { return fixedNow },
		}),
		ConfirmURL: "/login/confirm",
		Now:        func() time.Time { return fixedNow },
	})

	_, err = authenticator.CreateLoginLink(context.Background(), "nobody@example.com")

	if got, want := err, simpleauth.ErrUserNotFound; got != want {
		t.Fatalf("err=%v, want %v", got, want)
	}
}

func TestRequestLoginLinkHonorsRateLimit(t *testing.T) {
	userID, err := simpleauth.NewUserID("123")
	if err != nil {
		t.Fatalf("creating user ID: %v", err)
	}
	store := &memoryMagicLinkStore{entries: map[string]magiclink.Entry{}}
	authenticator := magiclink.New(magiclink.Config{
		Store: store,
		Users: memoryUserStore{user: simpleauth.User{
			ID:          userID,
			Email:       "homer@example.com",
			SessionData: []byte(`{"userId":123}`),
		}},
		SessionManager: sessions.NewManager(sessions.Config{
			Store:      &memorySessionStore{sessions: map[string]sessions.Session{}},
			CookieName: "token",
			Now:        func() time.Time { return fixedNow },
		}),
		ConfirmURL: "/login/confirm",
		RateLimit:  1,
		Now:        func() time.Time { return fixedNow },
	})
	_, err = authenticator.CreateLoginLink(context.Background(), "homer@example.com")
	if err != nil {
		t.Fatalf("creating first login link: %v", err)
	}

	_, err = authenticator.CreateLoginLink(context.Background(), "homer@example.com")

	if got, want := err, magiclink.ErrRateLimitExceeded; got != want {
		t.Fatalf("err=%v, want %v", got, want)
	}
}
