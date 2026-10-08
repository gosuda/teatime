package transport

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/coder/websocket"
)

func Stream(ctx context.Context, ws *websocket.Conn) net.Conn {
	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(64 << 10)
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ping, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Ping(ping)
				cancel()
				if err != nil {
					_ = ws.CloseNow()
					return
				}
			}
		}
	}()
	return conn
}

// Bridge has bounded buffers and never retries an interrupted application request.
func Bridge(ctx context.Context, a, b net.Conn) {
	finished := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) { _, _ = io.CopyBuffer(dst, src, make([]byte, 32<<10)); finished <- struct{}{} }
	go copyOne(a, b)
	go copyOne(b, a)
	completed := 0
	select {
	case <-ctx.Done():
	case <-finished:
		completed++
	}
	_ = a.Close()
	_ = b.Close()
	for completed < 2 {
		<-finished
		completed++
	}
}
