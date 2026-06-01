package transport

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"
)

// wsConnWrapper overwrites the RemoteAddr method to preserve the original client's IP address.
type wsConnWrapper struct {
	net.Conn
	remoteAddr net.Addr
}

func (w *wsConnWrapper) RemoteAddr() net.Addr {
	return w.remoteAddr
}

// DialWS establishes a WebSocket connection over a pre-established net.Conn (e.g., uTLS connection)
// and wraps it into a net.Conn compatible object.
func DialWS(ctx context.Context, rawConn net.Conn, serverAddr, wsPath string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	// Crucial Fix: Use "ws" instead of "wss" because the underlying rawConn
	// is already an established uTLS encrypted channel. Setting it to "wss"
	// would trigger an erroneous double-TLS handshake.
	u := url.URL{
		Scheme: "ws",
		Host:   host,
		Path:   wsPath,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return rawConn, nil
			},
		},
	}

	options := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	wsConn, _, err := websocket.Dial(ctx, u.String(), options)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
}

// AcceptWS upgrades an incoming HTTP request into a WebSocket session and
// wraps it as a net.Conn.
//
// When trustProxyHeaders is true, X-Forwarded-For / X-Real-IP from the
// request are honoured to determine the real client address (use this
// only behind a trusted reverse proxy that overwrites/strips client-set
// XFF — Nginx, Caddy, Cloudflare). When false (default), the proxy
// headers are ignored entirely and r.RemoteAddr is used: this prevents
// an attacker reaching phantom-server directly from spoofing a source
// IP to evade rate limiting or get innocent IPs banned.
func AcceptWS(w http.ResponseWriter, r *http.Request, trustProxyHeaders bool) (net.Conn, error) {
	options := &websocket.AcceptOptions{
		// InsecureSkipVerify here disables the websocket Origin check,
		// NOT TLS verification. Phantom uses its own auth, so origin
		// filtering would only block legitimate clients.
		InsecureSkipVerify: true,
	}

	wsConn, err := websocket.Accept(w, r, options)
	if err != nil {
		return nil, err
	}

	nc := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)

	remoteAddrStr := ""
	if trustProxyHeaders {
		// Extract the real remote address from proxy headers. Only the
		// first comma-separated XFF value is used — that's the original
		// client per the de-facto standard.
		remoteAddrStr = r.Header.Get("X-Forwarded-For")
		if remoteAddrStr != "" {
			if idx := strings.Index(remoteAddrStr, ","); idx != -1 {
				remoteAddrStr = remoteAddrStr[:idx]
			}
			remoteAddrStr = strings.TrimSpace(remoteAddrStr)
		} else {
			remoteAddrStr = r.Header.Get("X-Real-IP")
		}
	}

	// Fallback (and default when not trusting proxy headers) to the
	// transport-level remote address.
	if remoteAddrStr == "" {
		remoteAddrStr = r.RemoteAddr
	}

	// If the address does not have a port, append a dummy one to satisfy net.ResolveTCPAddr
	if _, _, err := net.SplitHostPort(remoteAddrStr); err != nil {
		remoteAddrStr = remoteAddrStr + ":0"
	}

	remoteAddr, err := net.ResolveTCPAddr("tcp", remoteAddrStr)
	if err != nil {
		remoteAddr, _ = net.ResolveTCPAddr("tcp", r.RemoteAddr)
	}

	return &wsConnWrapper{Conn: nc, remoteAddr: remoteAddr}, nil
}
