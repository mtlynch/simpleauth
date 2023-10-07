//go:build dev

package sessions

import "github.com/mtlynch/jeff"

func extraOptions() []func(*jeff.Jeff) {
	return []func(*jeff.Jeff){
		jeff.Insecure,
	}
}
