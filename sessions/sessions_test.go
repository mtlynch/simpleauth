package sessions_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mtlynch/simpleauth/v3"
	"github.com/mtlynch/simpleauth/v3/sessions"
)

var fixedNow = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

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

func TestCreateAndLoadSession(t *testing.T) {
	store := &memorySessionStore{sessions: map[string]sessions.Session{}}
	manager := sessions.NewManager(sessions.Config{
		Store:      store,
		CookieName: "token",
		RequireTLS: false,
		Now:        func() time.Time { return fixedNow },
	})
	userID, err := simpleauth.NewUserID("123")
	if err != nil {
		t.Fatalf("creating user ID: %v", err)
	}

	rec := httptest.NewRecorder()
	if err := manager.CreateSession(context.Background(), rec, simpleauth.User{
		ID:          userID,
		Email:       "homer@example.com",
		SessionData: []byte(`{"userId":123,"isAdmin":true}`),
	}); err != nil {
		t.Fatalf("creating session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	var loaded sessions.Session
	handler := manager.LoadSession(http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) {
			var err error
			loaded, err = manager.SessionFromContext(r.Context())
			if err != nil {
				t.Fatalf("reading session from context: %v", err)
			}
		},
	))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got, want := loaded.UserID.String(), "123"; got != want {
		t.Errorf("loaded.UserID=%v, want %v", got, want)
	}
	if got, want := string(loaded.SessionData), `{"userId":123,"isAdmin":true}`; got != want {
		t.Errorf("loaded.SessionData=%v, want %v", got, want)
	}
}

func TestRequireSessionRedirectsWithoutSession(t *testing.T) {
	store := &memorySessionStore{sessions: map[string]sessions.Session{}}
	manager := sessions.NewManager(sessions.Config{
		Store:      store,
		CookieName: "token",
		RequireTLS: false,
		Now:        func() time.Time { return fixedNow },
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler := manager.RequireSession("/login")(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Fatal("protected handler ran without a session")
		},
	))
	handler.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusSeeOther; got != want {
		t.Fatalf("status=%v, want %v", got, want)
	}
	if got, want := rec.Header().Get("Location"), "/login"; got != want {
		t.Errorf("Location=%v, want %v", got, want)
	}
}
