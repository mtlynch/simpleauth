package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/mtlynch/jeff"
)

type (
	// Store provides the base level abstraction for implementing session
	// storage.
	Store interface {
		// Store persists the session in the backend with the given expiration
		// Implementation must return value exactly as it is received.
		// Value will be given as...
		Store(ctx context.Context, key, value []byte, exp time.Time) error
		// Fetch retrieves the session from the backend.  If err != nil or
		// value == nil, then it's assumed that the session is invalid and Jeff
		// will redirect.  Expired sessions must return nil error and nil value.
		// Unknown (not found) sessions must return nil error and nil value.
		Fetch(ctx context.Context, key []byte) (value []byte, err error)
		// Delete removes the session given by key from the store. Errors are
		// bubbled up to the caller.  Delete should not return an error on expired
		// or missing keys.
		Delete(ctx context.Context, key []byte) error
	}

	Key struct {
		key []byte
	}

	Session []byte
)

var ErrNoSessionFound = errors.New("no active session in request context")

func New(store Store) (Manager, error) {
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
