package netcheck

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"main/lib/dnscache"
	"main/lib/iocount"
	"main/lib/proxyconn"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/maxsupermanhd/lac/v2"
)

const (
	pingSamples = 3
	pingPort    = "443"
)

func CheckEndpointResolve(_ lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	domain := strings.Split(desc.Endpoint, "/")[0]
	addrs, err := d.DNS.LookupIP(ctx, domain)
	if errors.Is(err, dnscache.ErrByProxy) {
		return CheckResult{
			Brief:   "BY PROXY",
			Color:   "gray",
			Content: "No DNS method works through the proxy. The proxy resolves the names.",
		}
	}
	if err != nil {
		return err
	}
	content := "dns: " + d.DNS.Method()
	if d.Proxy != nil {
		content += ", via proxy " + d.Proxy.Host()
	}
	if len(addrs) == 1 {
		return CheckResult{
			Brief:     addrs[0].String(),
			BriefHTML: fmt.Sprintf(`<a href="%s">%s</a>`, "https://ipinfo.io/"+addrs[0].String(), addrs[0].String()),
			Content:   content,
			Success:   1,
		}
	}
	return CheckResult{
		Brief:     addrs[0].String() + " +" + strconv.Itoa(len(addrs)-1),
		BriefHTML: fmt.Sprintf(`<a href="%s">%s</a> +%d`, "https://ipinfo.io/"+addrs[0].String(), addrs[0].String(), len(addrs)-1),
		Content:   content,
		Success:   1,
	}
}

func CheckEndpointPing(_ lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	domain := strings.Split(desc.Endpoint, "/")[0]
	start := time.Now()
	addrs, err := d.DNS.LookupIP(ctx, domain)
	if d.Proxy != nil {
		target := domain
		if err == nil {
			target = addrs[0].String()
		} else if !errors.Is(err, dnscache.ErrByProxy) {
			return err
		}
		return pingThroughProxy(ctx, d.Proxy, domain, target, time.Since(start))
	}
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, `ping`, addrs[0].String(), `-w`, `4`, `-c`, `1`)
	o, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Brief:   "FAIL",
			Color:   "red",
			Success: -1,
			Content: fmt.Sprintf("%s\nexit code: %d\nerr: %s", string(o), cmd.ProcessState.ExitCode(), err.Error()),
		}
	}
	if cmd.ProcessState.ExitCode() == 0 {
		o2 := strings.Split(string(o), "\n")
		if len(o2) != 7 {
			return CheckResult{
				Brief:   "???",
				Color:   "black",
				Success: -1,
				Content: strconv.Itoa(len(o2)) + "\n" + string(o),
			}
		}
		o3 := strings.TrimPrefix(o2[len(o2)-2], "rtt min/avg/max/mdev = ")
		if o3 == "" {
			return CheckResult{
				Brief:   "FAIL",
				Color:   "red",
				Success: -1,
				Content: "o3 fail\n" + string(o),
			}
		}
		o4 := strings.Split(o3, "/")
		if len(o4) < 2 {
			return CheckResult{
				Brief:   "???",
				Color:   "black",
				Success: -1,
				Content: "o4 fail\n" + string(o),
			}
		}
		return CheckResult{
			Brief:   o4[0],
			Color:   "green",
			Success: 1,
		}
	}
	return CheckResult{
		Brief:   "FAIL",
		Color:   "red",
		Success: -1,
		Content: fmt.Sprintf("%s\nexit code: %d", string(o), cmd.ProcessState.ExitCode()),
	}
}

// pingThroughProxy measures the time to the TLS ServerHello of target:443 through the tunnel,
// because ICMP cannot go through the proxy.
func pingThroughProxy(ctx context.Context, p *proxyconn.Proxy, domain, target string, lookup time.Duration) error {
	ms := func(x time.Duration) float64 { return float64(x.Microseconds()) / 1000 }
	addr := net.JoinHostPort(target, pingPort)
	var best string
	var failed []string
	bestHello := time.Duration(-1)
	got := 0
	for sample := range pingSamples {
		if ctx.Err() != nil {
			break
		}
		t0 := time.Now()
		conn, t, err := p.DialTarget(ctx, addr)
		if _, ok := errors.AsType[proxyconn.ErrProxy](err); ok {
			return err
		}
		hc := &helloConn{Conn: conn}
		if err == nil {
			err = tls.Client(hc, &tls.Config{ServerName: domain}).HandshakeContext(ctx)
			if errors.Is(err, errStopAfterHello) && !hc.received.IsZero() {
				err = nil
			}
			closeErr := conn.Close()
			// After a context timeout, crypto/tls already closed the conn.
			if err != nil && errors.Is(closeErr, net.ErrClosed) {
				closeErr = nil
			}
			err = errors.Join(err, closeErr)
		}
		events := []struct {
			name string
			at   time.Time
		}{
			{"connected to the proxy", t.ProxyConnected},
			{"TLS to the proxy done", t.ProxyTLS},
			{"tunnel open (reply from the proxy)", t.TunnelOpen},
			{"ClientHello sent", hc.sent},
			{"ServerHello received", hc.received},
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "sample %d: t0 start", sample+1)
		for i, e := range events {
			// Only an https:// proxy has this step. A TLS failure to the proxy returned ErrProxy above.
			if i == 1 && e.at.IsZero() {
				continue
			}
			if e.at.IsZero() {
				fmt.Fprintf(&sb, "; %s: did not occur", e.name)
				break
			}
			fmt.Fprintf(&sb, "; +%.1f ms %s", ms(e.at.Sub(t0)), e.name)
		}
		if err != nil {
			fmt.Fprintf(&sb, "; +%.1f ms error: %s", ms(time.Since(t0)), err)
			failed = append(failed, sb.String())
			continue
		}
		got++
		if h := hc.received.Sub(t0); bestHello < 0 || h < bestHello {
			bestHello = h
			best = sb.String()
		}
	}
	info := fmt.Sprintf("Target %s, server name %s. Times are since the start of the sample (t0). The DNS lookup before the samples took %.1f ms.", addr, domain, ms(lookup))
	if got == 0 {
		return CheckResult{
			Brief:   "FAIL",
			Color:   "red",
			Success: -1,
			Content: fmt.Sprintf("No ServerHello in %d samples.\n%s\n%s", len(failed), strings.Join(failed, "\n"), info),
		}
	}
	content := fmt.Sprintf("Time to the TLS ServerHello through the proxy. Best of %d samples with a ServerHello:\n%s", got, best)
	if len(failed) > 0 {
		content += "\nSamples with no ServerHello:\n" + strings.Join(failed, "\n")
	}
	return CheckResult{
		Brief:   fmt.Sprintf("%.1f", ms(bestHello)),
		Color:   "green",
		Success: 1,
		Content: content + "\n" + info,
	}
}

var errStopAfterHello = errors.New("stop after the ServerHello")

// helloConn gives crypto/tls only the first record from the server, then errStopAfterHello.
// Thus the handshake stops after the ServerHello, before the certificate check.
type helloConn struct {
	net.Conn
	sent, received time.Time
	record         []byte
	done           bool
}

func (c *helloConn) Write(b []byte) (int, error) {
	if c.sent.IsZero() {
		c.sent = time.Now()
	}
	return c.Conn.Write(b)
}

func (c *helloConn) Read(b []byte) (int, error) {
	if len(c.record) == 0 {
		if c.done {
			return 0, errStopAfterHello
		}
		c.done = true
		header := make([]byte, 5)
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			return 0, err
		}
		// Record type 22 is a handshake record, and message type 2 is ServerHello.
		if header[0] == 22 && len(body) > 0 && body[0] == 2 {
			c.received = time.Now()
		}
		c.record = append(header, body...)
	}
	n := copy(b, c.record)
	c.record = c.record[n:]
	return n, nil
}

func NewDefaultRequest(cfg lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription, proto string, tlsVer uint16, protos *http.Protocols) (*http.Client, *http.Request, error) {
	if protos == nil {
		protos = &http.Protocols{}
		protos.SetHTTP1(true)
	}
	cl := &http.Client{
		Transport: &http.Transport{
			ReadBufferSize: 1,
			TLSClientConfig: &tls.Config{
				MinVersion: tlsVer,
				MaxVersion: tlsVer,
			},
			DisableKeepAlives:  true,
			DisableCompression: true,
			IdleConnTimeout:    time.Millisecond,
			Protocols:          protos,
			DialContext:        d.DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, cfg.GetDString("GET", "httpMethod"), proto+"://"+desc.Endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("new req: %w", err)
	}
	return cl, req, nil
}

func CheckEndpointPlainHTTP(cfg lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	cl, req, err := NewDefaultRequest(cfg, ctx, d, desc, "http", 0, nil)
	if err != nil {
		return err
	}
	return CheckReq(cfg, cl, req, desc)
}

func CheckEndpointTLS12(cfg lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	cl, req, err := NewDefaultRequest(cfg, ctx, d, desc, "https", tls.VersionTLS12, nil)
	if err != nil {
		return err
	}
	return CheckReq(cfg, cl, req, desc)
}

func CheckEndpointTLS12HTTP2(cfg lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	cl, req, err := NewDefaultRequest(cfg, ctx, d, desc, "https", tls.VersionTLS12, protos)
	if err != nil {
		return err
	}
	return CheckReq(cfg, cl, req, desc)
}

func CheckEndpointTLS13(cfg lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	cl, req, err := NewDefaultRequest(cfg, ctx, d, desc, "https", tls.VersionTLS13, nil)
	if err != nil {
		return err
	}
	return CheckReq(cfg, cl, req, desc)
}

func CheckEndpointTLS13HTTP2(cfg lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	cl, req, err := NewDefaultRequest(cfg, ctx, d, desc, "https", tls.VersionTLS13, protos)
	if err != nil {
		return err
	}
	return CheckReq(cfg, cl, req, desc)
}

func CheckEndpointTLS13ECH(cfg lac.Conf, ctx context.Context, d *Dialer, desc EndpointDescription) error {
	domain := strings.Split(desc.Endpoint, "/")[0]
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: domain,
	}
	cl := &http.Client{
		Transport: &http.Transport{
			ReadBufferSize:     1,
			TLSClientConfig:    tlsConfig,
			DisableKeepAlives:  true,
			DisableCompression: true,
			IdleConnTimeout:    time.Millisecond,
			TLSNextProto:       nil,
			ForceAttemptHTTP2:  false,
			HTTP2:              nil,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ech, err := d.DNS.LookupECH(ctx, domain)
				if errors.Is(err, dnscache.ErrNoECH) || errors.Is(err, dnscache.ErrByProxy) {
					return nil, CheckResult{
						Brief:   "NODNS",
						Color:   "gray",
						Content: err.Error(),
					}
				}
				if err != nil {
					return nil, err
				}
				tlsConfig.EncryptedClientHelloConfigList = ech
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					return nil, errors.Join(err, conn.Close())
				}
				state := tlsConn.ConnectionState()
				if !state.ECHAccepted {
					return nil, errors.Join(CheckResult{
						Brief:   "UNUSED",
						Color:   "yellow",
						Success: -1,
					}, tlsConn.Close())
				}
				return tlsConn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	return CheckReq(cfg, cl, req, desc)
}

func CheckReq(cfg lac.Conf, cl *http.Client, req *http.Request, desc EndpointDescription) (err error) {
	if desc.UserAgent != "" {
		req.Header.Set("User-Agent", desc.UserAgent) //"Mozilla/5.0 (Android 16; Mobile; rv:154.0) Gecko/154.0 Firefox/154.0")
	} else {
		req.Header.Add("User-Agent", "netcheck github.com/maxsupermanhd/netcheck")
	}
	padTotal := cfg.GetDInt(0, "padTotalBytes")
	padMax := cfg.GetDInt(2_000, "padHeaderMaxBytes")
	for i := 0; padTotal > 0; i++ {
		req.Header.Set("X-Pad-"+strconv.Itoa(i), strings.Repeat("X", padMax))
		padTotal -= padMax
	}
	rsp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("req do: %w", err)
	}
	defer func() {
		err = errors.Join(err, rsp.Body.Close())
	}()
	if rsp.StatusCode/100 == 3 {
		return CheckResult{
			Brief:   "REDIR",
			Color:   "yellow",
			Success: 0,
			Content: "redirects to: " + rsp.Header.Get("Location"),
		}
	}
	if rsp.StatusCode != 200 {
		return CheckResult{
			Brief:   strconv.Itoa(rsp.StatusCode),
			Color:   "yellow",
			Success: 0,
		}
	}
	body := iocount.NewCounterReader(rsp.Body)
	_, err = io.ReadAll(body)
	if err != nil {
		return ErrPartialRead{err: err, got: int(body.Count), need: int(rsp.ContentLength)}
	}
	if body.Count < 50_000 && !desc.SmallResponse {
		return CheckResult{
			Brief:   "SMALL",
			Color:   "yellow",
			Success: 0,
			Content: "Response too small: " + strconv.Itoa(int(body.Count)) + " bytes",
		}
	}
	return nil
}

type ErrPartialRead struct {
	err  error
	got  int
	need int
}

func (e ErrPartialRead) Error() string {
	return fmt.Sprintf("partial read, got %d need %d: %s", e.got, e.need, e.err.Error())
}

func (e ErrPartialRead) Is(target error) bool {
	var ok bool
	_, ok = target.(ErrPartialRead)
	if ok {
		return true
	}
	_, ok = target.(*ErrPartialRead)
	if ok {
		return true
	}
	return false
}
