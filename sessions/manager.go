package sessions

import (
	"context"
	"log"
	"net/http"

	"github.com/mtlynch/jeff"
)

// manager implements the SessionManager interface by wrapping the jeff sessions
// package.
type manager struct {
	j *jeff.Jeff
}

func (m manager) CreateSession(w http.ResponseWriter, ctx context.Context, key Key, session Session) error {
	return m.j.Set(ctx, w, key.Bytes(), session)
}

func (m manager) SessionFromContext(ctx context.Context) (Session, error) {
	sess := jeff.ActiveSession(ctx)
	if len(sess.Key) == 0 {
		return Session{}, ErrNoSessionFound
	}

	return sess.Meta, nil
}

func (m manager) EndSession(ctx context.Context, w http.ResponseWriter) {
	sess := jeff.ActiveSession(ctx)
	if len(sess.Key) > 0 {
		if err := m.j.Delete(ctx, sess.Key); err != nil {
			log.Printf("failed to delete session: %v", err)
		}
	}

	if err := m.j.Clear(ctx, w); err != nil {
		log.Printf("failed to clear session: %v", err)
	}
}

func (m manager) WrapRequest(next http.Handler) http.Handler {
	return m.j.Public(next)
}
