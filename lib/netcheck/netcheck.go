package netcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"main/lib/iocount"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func CheckEndpointResolve(desc EndpointDescription, timeout time.Duration) error {
	ctx, ctxCancel := context.WithTimeout(context.Background(), timeout)
	defer ctxCancel()
	domain := strings.Split(desc.Endpoint, "/")[0]
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return ErrNoDnsRecords
	}
	if len(addrs) == 1 {
		return ErrDnsResolved{
			Brief: addrs[0].String(),
			Res:   addrs,
		}
	}
	return ErrDnsResolved{
		Brief: addrs[0].String() + " +" + strconv.Itoa(len(addrs)-1),
		Res:   addrs,
	}
}

func CheckEndpointPlainHTTP(desc EndpointDescription, timeout time.Duration) error {
	cl := &http.Client{
		Transport: http.DefaultTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, ctxCancel := context.WithTimeout(context.Background(), timeout)
	defer ctxCancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0")
	return checkReq(cl, req)
}

func CheckEndpointTLS12(desc EndpointDescription, timeout time.Duration) error {
	cl := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			ReadBufferSize: 1,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout:   timeout,
			DisableKeepAlives:     true,
			DisableCompression:    false,
			IdleConnTimeout:       timeout,
			ResponseHeaderTimeout: timeout,
			TLSNextProto:          nil,
			ForceAttemptHTTP2:     false,
			HTTP2:                 nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, ctxCancel := context.WithTimeout(context.Background(), timeout)
	defer ctxCancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0")
	return checkReq(cl, req)
}

func CheckEndpointTLS13(desc EndpointDescription, timeout time.Duration) error {
	cl := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			ReadBufferSize: 1,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
			},
			TLSHandshakeTimeout:   timeout,
			DisableKeepAlives:     true,
			DisableCompression:    false,
			IdleConnTimeout:       timeout,
			ResponseHeaderTimeout: timeout,
			TLSNextProto:          nil,
			ForceAttemptHTTP2:     false,
			HTTP2:                 nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, ctxCancel := context.WithTimeout(context.Background(), timeout)
	defer ctxCancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0")
	return checkReq(cl, req)
}

func CheckEndpointTLS13ECH(desc EndpointDescription, timeout time.Duration) error {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	domain := strings.Split(desc.Endpoint, "/")[0]
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: domain,
	}
	cl := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			ReadBufferSize:        1,
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   timeout,
			DisableKeepAlives:     true,
			DisableCompression:    false,
			IdleConnTimeout:       timeout,
			ResponseHeaderTimeout: timeout,
			TLSNextProto:          nil,
			ForceAttemptHTTP2:     false,
			HTTP2:                 nil,
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
					return nil, ErrEchNotUsed
				}
				return tlsConn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, ctxCancel := context.WithTimeout(context.Background(), timeout)
	defer ctxCancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+desc.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("new req: %w", err)
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0")
	return checkReq(cl, req)
}

func checkReq(cl *http.Client, req *http.Request) error {
	rsp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("req do: %w", err)
	}
	if rsp.StatusCode/100 == 3 {
		return ErrRedir{to: rsp.Header.Get("Location")}
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
	return nil, ErrNoEchDns
}

var (
	ErrEchNotUsed   = errors.New("ech not used")
	ErrNoEchDns     = errors.New("no https record")
	ErrNoDnsRecords = errors.New("no dns records")
)

type ErrRedir struct {
	to string
}

func (e ErrRedir) Error() string {
	return "redirect: " + strconv.Quote(e.to)
}

func (e ErrRedir) Is(target error) bool {
	var ok bool
	_, ok = target.(ErrRedir)
	if ok {
		return true
	}
	_, ok = target.(*ErrRedir)
	if ok {
		return true
	}
	return false
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

type ErrDnsResolved struct {
	Brief string
	Res   []net.IP
}

func (e ErrDnsResolved) Error() string {
	return e.Brief
}

func (e ErrDnsResolved) Is(target error) bool {
	var ok bool
	_, ok = target.(ErrDnsResolved)
	if ok {
		return true
	}
	_, ok = target.(*ErrDnsResolved)
	if ok {
		return true
	}
	return false
}
