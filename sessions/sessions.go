package sessions

import (
	"database/sql"
	"errors"

	"github.com/mtlynch/jeff"
	jeff_sqlite "github.com/mtlynch/jeff/sqlite"
)

type (
	Key struct {
		key []byte
	}

	Session []byte
)

var ErrNoSessionFound = errors.New("no active session in request context")

func New(sqliteDB *sql.DB) (Manager, error) {
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

func KeyFromBytes(b []byte) Key {
	return Key{
		key: b,
	}
}

func (k Key) Bytes() []byte {
	return k.key
}
