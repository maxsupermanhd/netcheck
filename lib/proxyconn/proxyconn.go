package proxyconn

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

type Proxy struct {
	u       *url.URL
	forward net.Dialer
}

// Timing has the times of the steps in DialTarget. A step that did not occur has the zero time.
type Timing struct {
	ProxyConnected time.Time
	ProxyTLS       time.Time // https:// only
	TunnelOpen     time.Time
}

// ErrProxy is a failure before the proxy accepted the request.
// Stage is "connect", "auth", "refused" or "dns".
type ErrProxy struct {
	Stage string
	Err   error
}

func (e ErrProxy) Error() string {
	return "proxy " + e.Stage + ": " + e.Err.Error()
}

func (e ErrProxy) Unwrap() error {
	return e.Err
}

func New(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// The text of url.Error contains the full URL with the password.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return nil, fmt.Errorf("proxy url does not parse: %w", err)
	}
	defaultPort := map[string]string{"http": "8080", "https": "443", "socks5": "1080", "socks5h": "1080"}[u.Scheme]
	if defaultPort == "" {
		return nil, fmt.Errorf("proxy scheme %q is not supported, use http, https, socks5 or socks5h", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("proxy url has no host")
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), defaultPort)
	}
	return &Proxy{u: u}, nil
}

func (p *Proxy) Host() string {
	return p.u.Host
}

// DialTarget opens a tunnel to addr. addr is "host:port", and host can be an IP or a name.
func (p *Proxy) DialTarget(ctx context.Context, addr string) (net.Conn, Timing, error) {
	var t Timing
	conn, err := p.forward.DialContext(ctx, "tcp", p.u.Host)
	if err != nil {
		return nil, t, ErrProxy{Stage: "connect", Err: err}
	}
	t.ProxyConnected = time.Now()
	if p.u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: p.u.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, t, errors.Join(ErrProxy{Stage: "connect", Err: err}, conn.Close())
		}
		conn = tlsConn
		t.ProxyTLS = time.Now()
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, t, errors.Join(ErrProxy{Stage: "connect", Err: err}, conn.Close())
		}
	}
	if p.u.Scheme == "socks5" || p.u.Scheme == "socks5h" {
		err = p.socks5(conn, addr)
	} else {
		err = p.httpConnect(conn, addr)
	}
	if err != nil {
		return nil, t, errors.Join(err, conn.Close())
	}
	t.TunnelOpen = time.Now()
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, t, errors.Join(err, conn.Close())
	}
	return conn, t, nil
}

var socksReplies = map[byte]string{
	0x01: "general failure",
	0x02: "not allowed by the proxy rules",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TTL expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}

func (p *Proxy) socks5(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("port %q: %w", portStr, err)
	}
	methods := []byte{0x00}
	if p.u.User != nil {
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return ErrProxy{Stage: "connect", Err: err}
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return ErrProxy{Stage: "connect", Err: err}
	}
	if b[0] != 0x05 {
		return ErrProxy{Stage: "refused", Err: fmt.Errorf("socks version %d in the reply", b[0])}
	}
	switch b[1] {
	case 0x00:
	case 0x02:
		if p.u.User == nil {
			return ErrProxy{Stage: "auth", Err: errors.New("the proxy asks for a password")}
		}
		user := p.u.User.Username()
		pass, _ := p.u.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return ErrProxy{Stage: "auth", Err: errors.New("user or password is longer than 255 bytes")}
		}
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := conn.Write(req); err != nil {
			return ErrProxy{Stage: "connect", Err: err}
		}
		if _, err := io.ReadFull(conn, b[:2]); err != nil {
			return ErrProxy{Stage: "connect", Err: err}
		}
		if b[1] != 0x00 {
			return ErrProxy{Stage: "auth", Err: errors.New("the proxy rejected the user or password")}
		}
	case 0xFF:
		return ErrProxy{Stage: "auth", Err: errors.New("the proxy accepts no offered auth method")}
	default:
		return ErrProxy{Stage: "refused", Err: fmt.Errorf("the proxy selected unknown auth method %d", b[1])}
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			req = append(req, 0x01)
		} else {
			req = append(req, 0x04)
		}
		req = append(req, ip.AsSlice()...)
	} else {
		if len(host) > 255 {
			return fmt.Errorf("host name is longer than 255 bytes: %s", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return ErrProxy{Stage: "connect", Err: err}
	}
	if _, err := io.ReadFull(conn, b); err != nil {
		return ErrProxy{Stage: "connect", Err: err}
	}
	if b[1] != 0x00 {
		reason, ok := socksReplies[b[1]]
		if !ok {
			reason = "unknown reply"
		}
		err := fmt.Errorf("socks reply 0x%02x: %s", b[1], reason)
		// For these codes the proxy accepted the request, and the target failed.
		if b[1] >= 0x03 && b[1] <= 0x06 {
			return err
		}
		return ErrProxy{Stage: "refused", Err: err}
	}
	var boundLen int
	switch b[3] {
	case 0x01:
		boundLen = 4
	case 0x04:
		boundLen = 16
	case 0x03:
		if _, err := io.ReadFull(conn, b[:1]); err != nil {
			return ErrProxy{Stage: "connect", Err: err}
		}
		boundLen = int(b[0])
	default:
		return ErrProxy{Stage: "refused", Err: fmt.Errorf("socks reply has unknown address type %d", b[3])}
	}
	if _, err := io.ReadFull(conn, make([]byte, boundLen+2)); err != nil {
		return ErrProxy{Stage: "connect", Err: err}
	}
	return nil
}

func (p *Proxy) httpConnect(conn net.Conn, addr string) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if p.u.User != nil {
		pass, _ := p.u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(p.u.User.Username()+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		return ErrProxy{Stage: "connect", Err: err}
	}
	br := bufio.NewReader(conn)
	rsp, err := http.ReadResponse(br, req)
	if err != nil {
		return ErrProxy{Stage: "refused", Err: fmt.Errorf("CONNECT reply: %w", err)}
	}
	if rsp.StatusCode/100 != 2 {
		err := fmt.Errorf("CONNECT reply: %s", rsp.Status)
		closeErr := rsp.Body.Close()
		switch rsp.StatusCode {
		case http.StatusProxyAuthRequired:
			return errors.Join(ErrProxy{Stage: "auth", Err: err}, closeErr)
		case http.StatusBadGateway, http.StatusGatewayTimeout:
			// The proxy accepted the request, and the target failed.
			return errors.Join(err, closeErr)
		default:
			return errors.Join(ErrProxy{Stage: "refused", Err: err}, closeErr)
		}
	}
	// The checks speak first (HTTP, TLS, DNS), so the target sends no data before the client.
	// Data in the buffer here means that the proxy reply is not valid.
	if br.Buffered() > 0 {
		return ErrProxy{Stage: "refused", Err: errors.New("the proxy sent data after the CONNECT reply")}
	}
	return nil
}
