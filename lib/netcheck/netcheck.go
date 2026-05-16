package netcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"main/lib/iocount"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func CheckEndpointResolve(ctx context.Context, desc EndpointDescription) error {
	domain := strings.Split(desc.Endpoint, "/")[0]
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return CheckResult{
			Brief:   "FAIL",
			Color:   "red",
			Success: -1,
		}
	}
	if len(addrs) == 1 {
		return CheckResult{
			Brief:     addrs[0].String(),
			BriefHTML: fmt.Sprintf(`<a href="%s">%s</a>`, "https://ipinfo.io/"+addrs[0].String(), addrs[0].String()),
			Success:   1,
		}
	}
	return CheckResult{
		Brief:     addrs[0].String() + " +" + strconv.Itoa(len(addrs)-1),
		BriefHTML: fmt.Sprintf(`<a href="%s">%s</a> +%d`, "https://ipinfo.io/"+addrs[0].String(), addrs[0].String(), len(addrs)-1),
		Success:   1,
	}
}

func CheckEndpointPing(ctx context.Context, desc EndpointDescription) error {
	domain := strings.Split(desc.Endpoint, "/")[0]
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return CheckResult{
			Brief:   "FAIL",
			Color:   "red",
			Success: -1,
			Content: "it was dns",
		}
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
			Content: string(o),
		}
	}
	return CheckResult{
		Brief:   "FAIL",
		Color:   "red",
		Success: -1,
		Content: fmt.Sprintf("%s\nexit code: %d", string(o), cmd.ProcessState.ExitCode()),
	}
}

func CheckEndpointPlainHTTP(ctx context.Context, desc EndpointDescription) error {
	cl := &http.Client{
		Transport: http.DefaultTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	req.Header.Add("User-Agent", "netcheck github.com/maxsupermanhd/netcheck")
	return checkReq(cl, req)
}

func CheckEndpointTLS12(ctx context.Context, desc EndpointDescription) error {
	cl := &http.Client{
		Transport: &http.Transport{
			ReadBufferSize: 1,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
			DisableKeepAlives:  true,
			DisableCompression: false,
			TLSNextProto:       nil,
			ForceAttemptHTTP2:  false,
			HTTP2:              nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	req.Header.Add("User-Agent", "netcheck github.com/maxsupermanhd/netcheck")
	return checkReq(cl, req)
}

func CheckEndpointTLS13(ctx context.Context, desc EndpointDescription) error {
	cl := &http.Client{
		Transport: &http.Transport{
			ReadBufferSize: 1,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
			},
			DisableKeepAlives:  true,
			DisableCompression: false,
			TLSNextProto:       nil,
			ForceAttemptHTTP2:  false,
			HTTP2:              nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	req.Header.Add("User-Agent", "netcheck github.com/maxsupermanhd/netcheck")
	return checkReq(cl, req)
}

func CheckEndpointTLS13ECH(ctx context.Context, desc EndpointDescription) error {
	dialer := &net.Dialer{}
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
			DisableCompression: false,
			TLSNextProto:       nil,
			ForceAttemptHTTP2:  false,
			HTTP2:              nil,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ech, err := lookupHTTPS(domain)
				if err != nil {
					return nil, err
				}
				tlsConfig.EncryptedClientHelloConfigList = ech
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(conn, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					return nil, err
				}
				state := tlsConn.ConnectionState()
				if !state.ECHAccepted {
					return nil, CheckResult{
						Brief:   "UNUSED",
						Color:   "yellow",
						Success: -1,
					}
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
	req.Header.Add("User-Agent", "netcheck github.com/maxsupermanhd/netcheck")
	return checkReq(cl, req)
}

func checkReq(cl *http.Client, req *http.Request) error {
	rsp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("req do: %w", err)
	}
	if rsp.StatusCode/100 == 3 {
		return CheckResult{
			Brief:   "REDIR",
			Color:   "yellow",
			Success: 0,
			Content: "redirects to: " + rsp.Header.Get("Location"),
		}
	}
	body := iocount.NewCounterReader(rsp.Body)
	_, err = io.ReadAll(body)
	if err != nil {
		return ErrPartialRead{err: err, got: int(body.Count), need: int(rsp.ContentLength)}
	}
	return nil
}

func lookupHTTPS(domain string) (ret []byte, err error) {

	var msg dnsmessage.Message
	msg.Header.ID = 12345
	msg.Header.RecursionDesired = true

	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain + "."),
		Type:  dnsmessage.TypeHTTPS,
		Class: dnsmessage.ClassINET,
	}

	msg.Questions = append(msg.Questions, q)

	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	addr := net.UDPAddr{
		Port: 53,
		IP:   net.ParseIP("8.8.8.8"),
	}
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(packed)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	var response dnsmessage.Message
	err = response.Unpack(buffer[:n])
	if err != nil {
		return nil, err
	}

	for _, answer := range response.Answers {
		if httpsRes, ok := answer.Body.(*dnsmessage.HTTPSResource); ok {
			for _, v := range httpsRes.Params {
				if v.Key == dnsmessage.SVCParamECH {
					return v.Value, nil
				}
			}
		}
	}
	return nil, CheckResult{
		Brief: "NODNS",
		Color: "gray",
	}
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
