//go:build !windows

package gjl

import (
	"os"
	"path/filepath"
	"strconv"
)

func ProfileAddress(development bool) (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base != "" {
		base = filepath.Join(base, "gjl")
	} else {
		base = filepath.Join(os.TempDir(), "gjl-"+strconv.Itoa(os.Geteuid()))
	}
	name := "daemon.sock"
	if development {
		name = "daemon-development.sock"
	}
	address := filepath.Join(base, name)
	return address, validateAddress(address)
}
