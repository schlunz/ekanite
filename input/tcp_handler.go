package input

import (
	"bufio"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// Handles connection with using the SyslogDelimiter.
func (s *TCPCollector) handleConnSyslog(conn net.Conn, c chan<- *Event) {
	stats.Add("tcpConnections", 1)
	defer func() {
		stats.Add("tcpConnections", -1)
		conn.Close()
	}()

	delimiter := NewSyslogDelimiter(msgBufSize)
	reader := bufio.NewReader(conn)
	var log string
	var match bool

	for {
		conn.SetReadDeadline(time.Now().Add(newlineTimeout))
		b, err := reader.ReadByte()
		if err != nil {
			stats.Add("tcpConnReadError", 1)
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				stats.Add("tcpConnReadTimeout", 1)
				log, match = delimiter.Vestige()
			} else if err == io.EOF {
				stats.Add("tcpConnReadEOF", 1)
				log, match = delimiter.Vestige()
			} else {
				stats.Add("tcpConnUnrecoverError", 1)
				return
			}
		} else {
			stats.Add("tcpBytesRead", 1)
			log, match = delimiter.Push(b)
		}
		if match {
			stats.Add("tcpEventsRx", 1)
			c <- &Event{
				Text:          log,
				Parsed:        s.parser.Parse(log),
				ReceptionTime: time.Now().UTC(),
				Sequence:      atomic.AddInt64(&sequenceNumber, 1),
				SourceIP:      conn.RemoteAddr().String(),
			}
		}
	}
}

// Handles connection with using the NetstrDelimiter (netstrings like delimiter).
func (s *TCPCollector) handleConnNetstr(conn net.Conn, c chan<- *Event) {
	stats.Add("tcpConnections", 1)
	defer func() {
		stats.Add("tcpConnections", -1)
		conn.Close()
	}()

	delimiter := NewNetstrDelimiter()
	reader := bufio.NewReader(conn)
	var match bool

	for {
		conn.SetReadDeadline(time.Now().Add(newlineTimeout))
		b, err := reader.ReadByte()
		if err != nil {
			stats.Add("tcpConnReadError", 1)
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				stats.Add("tcpConnReadTimeout", 1)
			} else if err == io.EOF {
				stats.Add("tcpConnReadEOF", 1)
			} else {
				stats.Add("tcpConnUnrecoverError", 1)
			}
			return
		} else {
			stats.Add("tcpBytesRead", 1)
			if match, err = delimiter.Push(b); err != nil {
				return
			}
		}
		if match {
			stats.Add("tcpEventsRx", 1)
			c <- &Event{
				Text:          delimiter.Result,
				Parsed:        s.parser.Parse(delimiter.Result),
				ReceptionTime: time.Now().UTC(),
				Sequence:      atomic.AddInt64(&sequenceNumber, 1),
				SourceIP:      conn.RemoteAddr().String(),
			}
		}
	}
}
