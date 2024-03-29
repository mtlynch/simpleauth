package sessions

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	"github.com/mtlynch/jeff"
	jeff_sqlite "github.com/mtlynch/jeff/sqlite"
)

type Manager struct {
	j *jeff.Jeff
}

func NewManager(sqliteDB *sql.DB) (Manager, error) {
	store, err := jeff_sqlite.New(sqliteDB)
	if err != nil {
		return Manager{}, err
	}
	options := []func(*jeff.Jeff){jeff.CookieName("token")}
	options = append(options, extraOptions()...)
	j := jeff.New(store, options...)
	return Manager{
		j: j,
	}, nil
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
