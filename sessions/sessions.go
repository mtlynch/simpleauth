package sessions

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/mtlynch/jeff"
	"github.com/mtlynch/jeff/sqlite"
)

type (
	Manager interface {
		CreateSession(http.ResponseWriter, context.Context, Key, Session) error
		SessionFromContext(context.Context) (Session, error)
		EndSession(context.Context, http.ResponseWriter)
		// WrapRequest wraps the given handler, adding the Session object (if
		// there's an active session) to the request context before passing control
		// to the next handler.
		WrapRequest(http.Handler) http.Handler
	}

	Key struct {
		key []byte
	}

	Session []byte
)

var ErrNoSessionFound = errors.New("no active session in request context")

func New(dbPath string) (Manager, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return manager{}, err
	}
	store, err := sqlite.New(db)
	if err != nil {
		return manager{}, err
	}
	options := []func(*jeff.Jeff){jeff.CookieName("token")}
	options = append(options, extraOptions()...)
	j := jeff.New(store, options...)
	return manager{
		j: j,
	}, nil
}

func KeyFromBytes(b []byte) Key {
	return Key{
		key: b,
	}
}

func (k Key) Bytes() []byte {
	return k.key
}
