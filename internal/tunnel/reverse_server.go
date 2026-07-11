package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// reverseDataOpcode is the first byte of every server->client reverse
// forward stream. The header written by the server is:
//
//	[reverseDataOpcode:1][targetLen:1][target: targetLen bytes]
//
// followed by the raw bidirectional byte pipe. Opcode 0x00 is reserved
// and never used on this path so the client can reject unknown opcodes
// by closing the stream.
const reverseDataOpcode byte = 0x01

// registerReverseSession adds a live session to the per-peer set used by
// the reverse listeners to open server->client streams.
func (s *Server) registerReverseSession(peer string, sess *quic.Conn) {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	if s.revSessions == nil {
		s.revSessions = make(map[string]map[*quic.Conn]struct{})
	}
	set := s.revSessions[peer]
	if set == nil {
		set = make(map[*quic.Conn]struct{})
		s.revSessions[peer] = set
	}
	set[sess] = struct{}{}
}

// unregisterReverseSession removes a session on handleSession return.
func (s *Server) unregisterReverseSession(peer string, sess *quic.Conn) {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	set := s.revSessions[peer]
	if set == nil {
		return
	}
	delete(set, sess)
	if len(set) == 0 {
		delete(s.revSessions, peer)
	}
}

// pickReverseSession returns a live QUIC session for the named peer,
// round-robining across that peer's currently registered sessions via an
// atomic cursor. Returns (nil, false) when the peer has no live session
// (offline), which the caller treats as "drop the incoming connection".
func (s *Server) pickReverseSession(peer string) (*quic.Conn, bool) {
	s.revMu.Lock()
	set := s.revSessions[peer]
	if len(set) == 0 {
		s.revMu.Unlock()
		return nil, false
	}
	conns := make([]*quic.Conn, 0, len(set))
	for c := range set {
		conns = append(conns, c)
	}
	s.revMu.Unlock()

	// Advance the round-robin cursor and return the first session whose
	// context is still live, scanning from the cursor position.
	n := uint64(len(conns))
	start := s.revRR.Add(1)
	for i := uint64(0); i < n; i++ {
		c := conns[(start+i)%n]
		if c.Context().Err() == nil {
			return c, true
		}
	}
	return nil, false
}

// startReverseListener binds the rule's listen address and tunnels each
// accepted TCP connection back to the rule's peer. Mirrors the client's
// startForwardInbound: the listener is closed on the stop channel so
// Accept returns promptly on shutdown. A bind/normalize failure is logged
// and disables just this rule — it does not take down the server.
func (s *Server) startReverseListener(rule config.ReverseForwardConfig) {
	normalized, defaultedLoopback, err := config.NormalizeReverseListen(rule.Listen)
	if err != nil {
		slog.Error("reverse listener: invalid listen address",
			"component", "reverse", "listen", rule.Listen, "peer", rule.Peer, "error", err)
		return
	}
	if defaultedLoopback {
		slog.Info("reverse listener defaulting to loopback; set an explicit host (e.g. 0.0.0.0) to expose it",
			"component", "reverse", "listen", normalized, "peer", rule.Peer)
	}

	ln, err := net.Listen("tcp", normalized)
	if err != nil {
		slog.Error("reverse listener: listen failed",
			"component", "reverse", "listen", normalized, "peer", rule.Peer, "error", err)
		return
	}
	slog.Info("reverse listener started",
		"component", "reverse", "listen", normalized, "target", rule.Target, "peer", rule.Peer)

	// Close the listener as soon as Stop fires so Accept returns promptly
	// instead of waiting for the next inbound connection.
	go func() {
		<-s.stopCh
		_ = ln.Close()
	}()

	for s.running.Load() {
		conn, err := ln.Accept()
		if err != nil {
			// Accept only fails on listener close (Stop) or a real
			// listener-level error. Either way exit instead of
			// busy-spinning on the same error forever.
			return
		}
		go s.handleReverseConn(conn, rule.Target, rule.Peer)
	}
}

// handleReverseConn opens a reverse stream to a live session for peer,
// writes the [opcode][len][target] header, then splices the two. When no
// session is live the incoming TCP conn is closed immediately.
func (s *Server) handleReverseConn(tcpConn net.Conn, target, peer string) {
	defer tcpConn.Close()

	sess, ok := s.pickReverseSession(peer)
	if !ok {
		slog.Debug("reverse: no live session, dropping connection",
			"component", "reverse", "peer", peer, "target", target, "remote", tcpConn.RemoteAddr())
		return
	}

	// len(target) must fit the single length byte. Defaulting guarantees a
	// non-empty target, and validation rejects long addresses, but guard
	// anyway so a bad rule can never emit a corrupt header.
	if len(target) == 0 || len(target) > 255 {
		slog.Warn("reverse: target length out of range, dropping",
			"component", "reverse", "peer", peer, "target", target, "len", len(target))
		return
	}

	openCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := sess.OpenStreamSync(openCtx)
	cancel()
	if err != nil {
		slog.Debug("reverse: open stream failed",
			"component", "reverse", "peer", peer, "target", target, "error", err)
		return
	}
	defer stream.Close()

	// Header: [reverseDataOpcode][targetLen][target...]
	header := make([]byte, 2+len(target))
	header[0] = reverseDataOpcode
	header[1] = byte(len(target))
	copy(header[2:], target)
	if _, err := stream.Write(header); err != nil {
		slog.Debug("reverse: header write failed",
			"component", "reverse", "peer", peer, "target", target, "error", err)
		return
	}

	slog.Debug("reverse: stream opened",
		"component", "reverse", "peer", peer, "target", target, "stream_id", int64(stream.StreamID()), "remote", tcpConn.RemoteAddr())

	pc := s.peerCountersByName(peer)
	s.spliceStream(stream, tcpConn, target,
		func(n int64) {
			s.bytesReceived.Add(uint64(n))
			if pc != nil && n > 0 {
				pc.bytesReceived.Add(uint64(n))
				pc.touch()
			}
		},
		func(n int64) {
			s.bytesSent.Add(uint64(n))
			if pc != nil && n > 0 {
				pc.bytesSent.Add(uint64(n))
				pc.touch()
			}
		})
}

// spliceStream runs the two-way copy between a QUIC stream and a plain
// conn, then the graceful-close / StreamCloseTimeoutSec drain dance. It
// is the shared core of the forward (handleStream) and reverse
// (handleReverseConn) paths so both behave identically. onRecv reports
// bytes copied stream->other (the tunnel receive direction) and onSent
// reports bytes copied other->stream (the send direction); either may be
// nil. Cancelling the stream unblocks a stuck copy.
func (s *Server) spliceStream(stream *quic.Stream, other net.Conn, logTarget string, onRecv, onSent func(n int64)) {
	errCh := make(chan error, 2)

	// stream -> other (data received from the peer over QUIC).
	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(other, stream, *bufPtr)
		if onRecv != nil {
			onRecv(n)
		}
		slog.Debug("upload finished", "component", "quic", "target", logTarget, "bytes", n, "error", err)
		errCh <- err
	}()

	// other -> stream (data sent to the peer over QUIC).
	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(stream, other, *bufPtr)
		if onSent != nil {
			onSent(n)
		}
		slog.Debug("download finished", "component", "quic", "target", logTarget, "bytes", n, "error", err)
		errCh <- err
	}()

	firstErr := <-errCh
	slog.Debug("first copy done, closing", "component", "quic", "target", logTarget, "err", firstErr)

	// If the first copy ended with an error (not clean EOF), the transfer
	// is already broken — no point waiting for the other half to drain.
	// Cancel the stream now so the second goroutine unblocks immediately.
	if firstErr != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}

	done := make(chan struct{})
	go func() { <-errCh; close(done) }()

	timer := time.NewTimer(time.Duration(s.config.QUIC.StreamCloseTimeoutSec) * time.Second)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
		slog.Debug("stream close timeout, aborting", "component", "quic", "target", logTarget)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		<-done
	}
	slog.Debug("stream fully closed", "component", "quic", "target", logTarget)
}
