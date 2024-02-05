package sessions

import (
	"context"
	"log"
	"net/http"

	"github.com/mtlynch/jeff"
)

// Manager wraps the jeff sessions package.
type Manager struct {
	j *jeff.Jeff
}

func (m Manager) CreateSession(w http.ResponseWriter, ctx context.Context, key Key, session Session) error {
	return m.j.Set(ctx, w, key.Bytes(), session)
}

func (m Manager) SessionFromContext(ctx context.Context) (Session, error) {
	sess := jeff.ActiveSession(ctx)
	if len(sess.Key) == 0 {
		return Session{}, ErrNoSessionFound
	}

	return sess.Meta, nil
}

func (m Manager) EndSession(ctx context.Context, w http.ResponseWriter) {
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

func (m Manager) WrapRequest(next http.Handler) http.Handler {
	return m.j.Public(next)
}
