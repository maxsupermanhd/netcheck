package dnscache

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"main/lib/proxyconn"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/maxsupermanhd/lac/v2"
	"golang.org/x/net/dns/dnsmessage"
)

const queryTimeout = 5 * time.Second

const (
	methodSystem   = "system"
	methodTCP      = "tcp"
	methodDoH      = "doh"
	methodHostname = "hostname"
)

var (
	ErrByProxy = errors.New("the proxy resolves the names")
	ErrNoECH   = errors.New("no ECH config in the HTTPS record")
)

type RCodeError dnsmessage.RCode

func (e RCodeError) Error() string {
	return "dns reply: " + dnsmessage.RCode(e).String()
}

type DialFunc func(ctx context.Context, addr string) (net.Conn, error)

type Resolver struct {
	dial         DialFunc
	proxied      bool
	doh          *http.Client
	tcpServer    string
	dohURL       string
	probeName    string
	probeTimeout time.Duration

	mu        sync.Mutex
	method    string
	methodErr error
	entries   map[entryKey]*entry
}

type entryKey struct {
	host  string
	qtype dnsmessage.Type
}

type entry struct {
	done  chan struct{}
	addrs []netip.Addr
	ech   []byte
	err   error
}

// New makes a resolver from the netcheck.dns config. A nil dial means no proxy.
func New(cfg lac.Conf, dial DialFunc) (*Resolver, error) {
	r := &Resolver{
		dial:         dial,
		proxied:      dial != nil,
		tcpServer:    cfg.GetDString("8.8.8.8:53", "tcpServer"),
		dohURL:       cfg.GetDString("https://1.1.1.1/dns-query", "dohURL"),
		probeName:    cfg.GetDString("dns.google", "probeName"),
		probeTimeout: time.Duration(cfg.GetDInt(3, "probeTimeoutSeconds")) * time.Second,
		method:       methodSystem,
		entries:      map[entryKey]*entry{},
	}
	// The servers must be IP literals, so the cache never needs a lookup for its own server.
	var errs []error
	if _, err := netip.ParseAddrPort(r.tcpServer); err != nil {
		errs = append(errs, fmt.Errorf("dns.tcpServer %q must be an IP and a port: %w", r.tcpServer, err))
	}
	if u, err := url.Parse(r.dohURL); err != nil {
		errs = append(errs, errors.New("dns.dohURL does not parse"))
	} else if _, err := netip.ParseAddr(u.Hostname()); u.Scheme != "https" || err != nil {
		errs = append(errs, fmt.Errorf("dns.dohURL %q must be an https URL with an IP host", u.Redacted()))
	}
	if r.probeName == "" {
		errs = append(errs, errors.New("dns.probeName must not be empty"))
	}
	if r.probeTimeout <= 0 {
		errs = append(errs, errors.New("dns.probeTimeoutSeconds must be above 0"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if !r.proxied {
		d := &net.Dialer{}
		r.dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	r.doh = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return r.dial(ctx, addr)
			},
		},
	}
	return r, nil
}

// Reset clears the cache. With a proxy, it also selects the DNS method for the next run.
func (r *Resolver) Reset(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = map[entryKey]*entry{}
	r.methodErr = nil
	if !r.proxied {
		return nil
	}
	r.doh.CloseIdleConnections()
	var errs []error
	for _, m := range []string{methodTCP, methodDoH, methodHostname} {
		pctx, cancel := context.WithTimeout(ctx, r.probeTimeout)
		var err error
		if m == methodHostname {
			var conn net.Conn
			conn, err = r.dial(pctx, net.JoinHostPort(r.probeName, "443"))
			if err == nil {
				err = conn.Close()
			}
		} else {
			_, _, err = r.query(pctx, m, r.probeName, dnsmessage.TypeA)
			if _, ok := errors.AsType[RCodeError](err); ok {
				err = nil
			}
		}
		cancel()
		if err == nil {
			r.method = m
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.describe(m), err))
		// The other methods use the same proxy, so they fail too.
		if pe, ok := errors.AsType[proxyconn.ErrProxy](err); ok && (pe.Stage == "connect" || pe.Stage == "auth") {
			r.methodErr = errors.Join(errs...)
			return r.methodErr
		}
	}
	r.methodErr = proxyconn.ErrProxy{Stage: "dns", Err: errors.Join(errs...)}
	return r.methodErr
}

func (r *Resolver) Method() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.describe(r.method)
}

func (r *Resolver) describe(method string) string {
	switch method {
	case methodTCP:
		return "tcp " + r.tcpServer
	case methodDoH:
		return "doh " + r.dohURL
	}
	return method
}

// LookupIP returns the IPv4 addresses of host.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	e, err := r.lookup(ctx, host, dnsmessage.TypeA)
	if err != nil {
		return nil, err
	}
	return e.addrs, e.err
}

func (r *Resolver) LookupECH(ctx context.Context, host string) ([]byte, error) {
	e, err := r.lookup(ctx, host, dnsmessage.TypeHTTPS)
	if err != nil {
		return nil, err
	}
	return e.ech, e.err
}

func (r *Resolver) lookup(ctx context.Context, host string, qtype dnsmessage.Type) (*entry, error) {
	key := entryKey{host: host, qtype: qtype}
	r.mu.Lock()
	if r.methodErr != nil {
		r.mu.Unlock()
		return nil, r.methodErr
	}
	if r.method == methodHostname {
		r.mu.Unlock()
		return nil, ErrByProxy
	}
	method := r.method
	e, ok := r.entries[key]
	if !ok {
		e = &entry{done: make(chan struct{})}
		r.entries[key] = e
		// The query does not use the context of the first caller.
		// Thus a caller with a timeout does not cancel the query for the other callers.
		go func() {
			qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), queryTimeout)
			defer cancel()
			if method == methodSystem && qtype == dnsmessage.TypeA {
				e.addrs, e.err = net.DefaultResolver.LookupNetIP(qctx, "ip4", host)
				for i := range e.addrs {
					e.addrs[i] = e.addrs[i].Unmap()
				}
			} else {
				e.addrs, e.ech, e.err = r.query(qctx, method, host, qtype)
			}
			close(e.done)
		}()
	}
	r.mu.Unlock()
	select {
	case <-e.done:
		return e, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// query sends one DNS question with DNS over TCP or DNS over HTTPS.
// The system method uses DNS over TCP direct to r.tcpServer, because the system resolver has no HTTPS records.
func (r *Resolver) query(ctx context.Context, method, host string, qtype dnsmessage.Type) (addrs []netip.Addr, ech []byte, err error) {
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(rand.N(1 << 16)), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	if method == methodDoH {
		msg.Header.ID = 0
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, nil, err
	}

	var reply []byte
	if method == methodDoH {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.dohURL, bytes.NewReader(packed))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		rsp, err := r.doh.Do(req)
		if err != nil {
			return nil, nil, err
		}
		reply, err = io.ReadAll(io.LimitReader(rsp.Body, 1<<16))
		err = errors.Join(err, rsp.Body.Close())
		if err != nil {
			return nil, nil, err
		}
		if rsp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("doh reply: %s", rsp.Status)
		}
	} else {
		var conn net.Conn
		conn, err = r.dial(ctx, r.tcpServer)
		if err != nil {
			return nil, nil, err
		}
		defer func() {
			err = errors.Join(err, conn.Close())
		}()
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetDeadline(deadline); err != nil {
				return nil, nil, err
			}
		}
		// DNS over TCP puts a 2-byte length before each message (RFC 1035 4.2.2).
		if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(packed))), packed...)); err != nil {
			return nil, nil, err
		}
		l := make([]byte, 2)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, nil, err
		}
		reply = make([]byte, binary.BigEndian.Uint16(l))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return nil, nil, err
		}
	}

	var rsp dnsmessage.Message
	if err := rsp.Unpack(reply); err != nil {
		return nil, nil, err
	}
	if rsp.Header.ID != msg.Header.ID {
		return nil, nil, fmt.Errorf("dns reply has ID %d, the question has ID %d", rsp.Header.ID, msg.Header.ID)
	}
	if rsp.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, nil, RCodeError(rsp.Header.RCode)
	}
	for _, a := range rsp.Answers {
		switch b := a.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, netip.AddrFrom4(b.A))
		case *dnsmessage.HTTPSResource:
			for _, v := range b.Params {
				if v.Key == dnsmessage.SVCParamECH {
					return nil, v.Value, nil
				}
			}
		}
	}
	if qtype == dnsmessage.TypeHTTPS {
		return nil, nil, ErrNoECH
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("no A records for %s", host)
	}
	return addrs, nil, nil
}
