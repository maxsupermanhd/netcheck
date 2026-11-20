package netcheck

import (
	"context"
	"errors"
	"fmt"
	"main/lib/dnscache"
	"main/lib/proxyconn"
	"net"

	"github.com/maxsupermanhd/lac/v2"
)

type Dialer struct {
	DNS    *dnscache.Resolver
	Proxy  *proxyconn.Proxy // nil means direct
	direct net.Dialer
}

// NewDialer makes the dialer for all checks. An empty proxyURL means direct.
func NewDialer(proxyURL string, dnsCfg lac.Conf) (*Dialer, error) {
	d := &Dialer{}
	var dial dnscache.DialFunc
	if proxyURL != "" {
		p, err := proxyconn.New(proxyURL)
		if err != nil {
			return nil, err
		}
		d.Proxy = p
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			conn, _, err := p.DialTarget(ctx, addr)
			return conn, err
		}
	}
	dns, err := dnscache.New(dnsCfg, dial)
	if err != nil {
		return nil, err
	}
	d.DNS = dns
	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("network %q is not supported", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := d.DNS.LookupIP(ctx, host)
	if errors.Is(err, dnscache.ErrByProxy) {
		conn, _, err := d.Proxy.DialTarget(ctx, addr)
		return conn, err
	}
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	// The dialer sends the IP and not the name, so the proxy uses the answer of the DNS cache.
	var errs []error
	for _, ip := range addrs {
		target := net.JoinHostPort(ip.String(), port)
		var conn net.Conn
		if d.Proxy == nil {
			conn, err = d.direct.DialContext(ctx, network, target)
		} else {
			conn, _, err = d.Proxy.DialTarget(ctx, target)
		}
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		// Another IP does not help when the proxy itself fails.
		if _, ok := errors.AsType[proxyconn.ErrProxy](err); ok || ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}
