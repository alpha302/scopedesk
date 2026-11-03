package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type DNSReply struct {
	Name      string `json:"name"`
	Type      uint16 `json:"type"`
	RCode     int    `json:"rcode"`
	Answers   int    `json:"answers"`
	Truncated bool   `json:"truncated"`
	Alias     bool   `json:"alias"`
}
type DNSObservation struct {
	State   string     `json:"state"`
	At      time.Time  `json:"observed_at"`
	Basis   string     `json:"basis"`
	Replies []DNSReply `json:"replies"`
}
type dnsCapture struct {
	mu       sync.Mutex
	replies  []DNSReply
	overflow bool
}
type dnsEvidenceConn struct {
	net.Conn
	capture           *dnsCapture
	tcp               bool
	mu                sync.Mutex
	queries           map[uint16]dnsmessage.Question
	readBuf, writeBuf []byte
}

func (c *dnsEvidenceConn) inspect(raw []byte, response bool) {
	var m dnsmessage.Message
	if m.Unpack(raw) != nil || len(m.Questions) != 1 || m.Response != response {
		return
	}
	q := m.Questions[0]
	if !response {
		c.queries[m.ID] = q
		return
	}
	if expected, ok := c.queries[m.ID]; !ok || expected != q {
		return
	}
	r := DNSReply{Name: strings.TrimSuffix(strings.ToLower(q.Name.String()), "."), Type: uint16(q.Type), RCode: int(m.RCode), Truncated: m.Truncated}
	for _, answer := range m.Answers {
		if answer.Header.Type == q.Type {
			r.Answers++
		}
		if answer.Header.Type == dnsmessage.TypeCNAME {
			r.Alias = true
		}
	}
	c.capture.mu.Lock()
	defer c.capture.mu.Unlock()
	if len(c.capture.replies) < 64 {
		c.capture.replies = append(c.capture.replies, r)
	} else {
		c.capture.overflow = true
	}
}
func (c *dnsEvidenceConn) feed(data []byte, response bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.tcp {
		c.inspect(data, response)
		return
	}
	buf := &c.writeBuf
	if response {
		buf = &c.readBuf
	}
	if len(*buf)+len(data) > 131074 {
		*buf = nil
		return
	}
	*buf = append(*buf, data...)
	for len(*buf) >= 2 {
		n := int(binary.BigEndian.Uint16((*buf)[:2]))
		if len(*buf) < n+2 {
			return
		}
		c.inspect((*buf)[2:n+2], response)
		*buf = (*buf)[n+2:]
	}
}
func (c *dnsEvidenceConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if n > 0 {
		c.feed(b[:n], false)
	}
	return n, e
}
func (c *dnsEvidenceConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.feed(b[:n], true)
	}
	return n, e
}

// Observe the resolver's existing traffic: no second resolver or extra query.
// PreferGo is required to expose DNS wire responses; never classify IsNotFound
// or error text as NXDOMAIN. RCODE is recursive-resolver evidence, not DNSSEC proof.
func captureResolver(base *net.Resolver) (*net.Resolver, *dnsCapture) {
	if base == nil {
		base = net.DefaultResolver
	}
	r := *base
	capture := &dnsCapture{}
	dial := r.Dial
	r.PreferGo = true
	r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		var conn net.Conn
		var err error
		if dial != nil {
			conn, err = dial(ctx, network, address)
		} else {
			conn, err = (&net.Dialer{}).DialContext(ctx, network, address)
		}
		if err != nil {
			return nil, err
		}
		return &dnsEvidenceConn{Conn: conn, capture: capture, tcp: strings.HasPrefix(network, "tcp"), queries: map[uint16]dnsmessage.Question{}}, nil
	}
	return &r, capture
}
func (c *dnsCapture) observation(host string, lookupErr error) *DNSObservation {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := &DNSObservation{State: "unknown", At: time.Now().UTC(), Basis: "resolver_wire_v1; single observation does not determine HTTP reachability", Replies: append([]DNSReply{}, c.replies...)}
	if c.overflow {
		return o
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	var aNX, aaaaNX, aEmpty, aaaaEmpty, conflict bool
	for _, r := range c.replies {
		if r.Name != host || r.Truncated {
			continue
		}
		if r.Type != uint16(dnsmessage.TypeA) && r.Type != uint16(dnsmessage.TypeAAAA) {
			continue
		}
		if r.RCode == 0 && r.Answers > 0 {
			o.State = "answer"
			return o
		}
		if r.RCode == 3 {
			if r.Type == 1 {
				aNX = true
			} else {
				aaaaNX = true
			}
		} else if r.RCode == 0 && r.Answers == 0 && !r.Alias {
			if r.Type == 1 {
				aEmpty = true
			} else {
				aaaaEmpty = true
			}
		} else {
			conflict = true
		}
	}
	if aNX && aaaaNX && !aEmpty && !aaaaEmpty && !conflict {
		o.State = "nxdomain_pending"
		return o
	}
	if aEmpty && aaaaEmpty && !aNX && !aaaaNX && !conflict {
		o.State = "nodata"
		return o
	}
	for _, r := range c.replies {
		if r.RCode == 2 {
			o.State = "servfail"
			return o
		}
		if r.RCode == 5 {
			o.State = "refused"
			return o
		}
	}
	if e, ok := lookupErr.(net.Error); ok && e.Timeout() {
		o.State = "timeout"
	}
	return o
}
