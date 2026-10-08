//go:build !windows

package gjl

import (
	"context"
	"errors"
	"net"
	"path/filepath"
)

func validateAddress(address string) error {
	if !filepath.IsAbs(address) {
		return errors.New("absolute_unix_socket_required")
	}
	return nil
}
func dial(ctx context.Context, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", address)
}
