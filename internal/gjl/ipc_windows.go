//go:build windows

package gjl

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

func validateAddress(address string) error {
	name := strings.TrimPrefix(address, `\\.\pipe\`)
	if !strings.HasPrefix(address, `\\.\pipe\`) || strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\\/\x00") {
		return errors.New("local_named_pipe_required")
	}
	return nil
}
func dial(ctx context.Context, address string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, address)
}
