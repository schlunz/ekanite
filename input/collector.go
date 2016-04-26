package input

import (
	"crypto/tls"
	"expvar"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

var sequenceNumber int64
var stats = expvar.NewMap("input")

func init() {
	sequenceNumber = time.Now().UnixNano()
}

const (
	newlineTimeout = time.Duration(1000 * time.Millisecond)
	msgBufSize     = 256
)

// Collector specifies the interface all network collectors must implement.
type Collector interface {
	Start(chan<- *Event) error
	Addr() net.Addr
}

// TCPCollector represents a network collector that accepts and handler TCP connections.
type TCPCollector struct {
	iface, fmt, delimType string
	parser                *RFC5424Parser
	addr                  net.Addr
	tlsConfig             *tls.Config
}

// UDPCollector represents a network collector that accepts UDP packets.
type UDPCollector struct {
	addr   *net.UDPAddr
	fmt    string
	parser *RFC5424Parser
}

// NewCollector returns a network collector of the specified type, that will bind
// to the given inteface on Start(). If config is non-nil, a secure Collector will
// be returned. Secure Collectors require the protocol be TCP.
func NewCollector(proto, iface, format, delimType string, tlsConfig *tls.Config) (Collector, error) {
	parser := NewRFC5424Parser()
	if format != "syslog" {
		return nil, fmt.Errorf("unsupported collector format")
	}
	var found bool
	for _, typ := range []string{"syslog", "netstr"} {
		if typ == delimType {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("unsupported delimiter type")
	}
	if strings.ToLower(proto) == "tcp" {
		return &TCPCollector{
			iface:     iface,
			fmt:       format,
			delimType: delimType,
			parser:    parser,
			tlsConfig: tlsConfig,
		}, nil
	} else if strings.ToLower(proto) == "udp" {
		addr, err := net.ResolveUDPAddr("udp", iface)
		if err != nil {
			return nil, err
		}

		return &UDPCollector{addr: addr, fmt: format, parser: parser}, nil
	}
	return nil, fmt.Errorf("unsupport collector protocol")
}

// Start instructs the TCPCollector to bind to the interface and accept connections.
func (s *TCPCollector) Start(c chan<- *Event) error {
	var ln net.Listener
	var err error
	if s.tlsConfig == nil {
		ln, err = net.Listen("tcp", s.iface)
	} else {
		ln, err = tls.Listen("tcp", s.iface, s.tlsConfig)
	}
	s.addr = ln.Addr()

	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			if s.delimType == "netstr" {
				go s.handleConnNetstr(conn, c)
			} else {
				go s.handleConnSyslog(conn, c)
			}
		}
	}()
	return nil
}

// Addr returns the net.Addr that the Collector is bound to, in a race-say manner.
func (s *TCPCollector) Addr() net.Addr {
	return s.addr
}

// Start instructs the UDPCollector to start reading packets from the interface.
func (s *UDPCollector) Start(c chan<- *Event) error {
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return err
	}

	go func() {
		buf := make([]byte, msgBufSize)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			stats.Add("udpBytesRead", int64(n))
			if err != nil {
				continue
			}
			log := strings.Trim(string(buf[:n]), "\r\n")
			stats.Add("udpEventsRx", 1)
			c <- &Event{
				Text:          log,
				Parsed:        s.parser.Parse(log),
				ReceptionTime: time.Now().UTC(),
				Sequence:      atomic.AddInt64(&sequenceNumber, 1),
				SourceIP:      addr.String(),
			}
		}
	}()
	return nil
}

// Addr returns the net.Addr to which the UDP collector is bound.
func (s *UDPCollector) Addr() net.Addr {
	return s.addr
}
