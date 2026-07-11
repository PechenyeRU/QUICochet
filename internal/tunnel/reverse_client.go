package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// reverseHeaderReadTimeout bounds how long we wait for the server to
	// send the [opcode][len][target] header before giving up on the stream
	// (slowloris guard). Cleared once the target is parsed. Mirrors the
	// server's inbound header read guard.
	reverseHeaderReadTimeout = 10 * time.Second
	// reverseDialTimeout bounds the client-local dial to a reverse target.
	reverseDialTimeout = 5 * time.Second
)

// acceptReverseStreams accepts server-opened bidi streams on conn and
// handles each as a reverse port-forward (ssh -R). The server is the only
// side that opens streams toward the client, so every accepted stream is a
// reverse forward. The loop exits cleanly when conn closes (AcceptStream
// errors) or on shutdown (c.running flips false / stopCh closed) — mirrors
// receiveDatagrams' lifecycle.
func (c *Client) acceptReverseStreams(conn *quic.Conn) {
	slog.Debug("reverse acceptor: start", "component", "reverse")
	defer slog.Debug("reverse acceptor: exit", "component", "reverse")
	for c.running.Load() {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			slog.Debug("reverse acceptor: accept error", "component", "reverse", "error", err)
			return
		}
		go c.handleReverseStream(stream)
	}
}

// handleReverseStream reads the reverse-forward header, enforces the accept
// policy, dials the client-local target and splices the two. The header is
// [opcode:1][targetLen:1][target: targetLen bytes]; a non-0x01 opcode or a
// disallowed target closes the stream without dialing.
func (c *Client) handleReverseStream(stream *quic.Stream) {
	defer stream.Close()

	// Slowloris guard: bound the header read, then clear the deadline for
	// the tunnelled lifetime once the target is parsed.
	_ = stream.SetReadDeadline(time.Now().Add(reverseHeaderReadTimeout))

	var hdr [2]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		slog.Debug("reverse: header read failed", "component", "reverse", "error", err)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	// Opcode 0x00 is reserved and never used on this path; reject anything
	// that is not the reverse-data opcode by closing the stream.
	if hdr[0] != reverseDataOpcode {
		slog.Debug("reverse: unknown opcode, closing", "component", "reverse", "opcode", hdr[0])
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}

	targetLen := int(hdr[1])
	if targetLen == 0 {
		slog.Debug("reverse: empty target, closing", "component", "reverse")
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	target := make([]byte, targetLen)
	if _, err := io.ReadFull(stream, target); err != nil {
		slog.Debug("reverse: target read failed", "component", "reverse", "error", err)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	targetAddr := string(target)

	// Default-deny: the server can never coerce a dial that is not
	// explicitly authorised by reverse_accept.
	if !c.config.ReverseAccept.Enabled || !c.isReverseTargetAllowed(targetAddr) {
		slog.Warn("rejected reverse target", "component", "reverse",
			"target", targetAddr, "enabled", c.config.ReverseAccept.Enabled)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, reverseDialTimeout)
	if err != nil {
		slog.Debug("reverse: dial failed", "component", "reverse", "target", targetAddr, "error", err)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	defer targetConn.Close()

	slog.Debug("reverse: stream accepted", "component", "reverse",
		"target", targetAddr, "stream_id", int64(stream.StreamID()))

	// stream->target is data received from the server; target->stream is
	// data sent back to the server.
	c.spliceStream(stream, targetConn, targetAddr,
		func(n int64) { c.bytesReceived.Add(uint64(n)) },
		func(n int64) { c.bytesSent.Add(uint64(n)) })
}

// isReverseTargetAllowed reports whether target is authorised by the
// reverse_accept allow list. Matching semantics (default deny):
//   - an allow entry that parses as host:port matches ONLY that exact host:port;
//   - an allow entry that is a bare host (no port) matches ANY port on that host;
//   - an empty allow list matches nothing.
//
// The caller has already checked ReverseAccept.Enabled.
func (c *Client) isReverseTargetAllowed(target string) bool {
	th, tp, err := net.SplitHostPort(target)
	if err != nil {
		// A reverse target is always host:port; if it does not parse it
		// cannot match any entry.
		return false
	}
	for _, entry := range c.config.ReverseAccept.Allow {
		if eh, ep, err := net.SplitHostPort(entry); err == nil {
			// Entry is host:port -> exact match only.
			if eh == th && ep == tp {
				return true
			}
			continue
		}
		// Entry is a bare host -> matches any port on that host.
		if entry == th {
			return true
		}
	}
	return false
}

// spliceStream runs the two-way copy between a QUIC stream and a plain conn,
// then the graceful-close / StreamCloseTimeoutSec drain dance. It is the
// reverse-path twin of handleStream's splice logic; the forward path is left
// untouched. onRecv reports bytes copied stream->other (tunnel receive
// direction) and onSent reports bytes copied other->stream (send direction);
// either may be nil. Cancelling the stream unblocks a stuck copy.
func (c *Client) spliceStream(stream *quic.Stream, other net.Conn, logTarget string, onRecv, onSent func(n int64)) {
	errCh := make(chan error, 2)

	// stream -> other (data received from the server over QUIC).
	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(other, stream, *bufPtr)
		if onRecv != nil {
			onRecv(n)
		}
		errCh <- err
	}()

	// other -> stream (data sent back to the server over QUIC).
	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(stream, other, *bufPtr)
		if onSent != nil {
			onSent(n)
		}
		errCh <- err
	}()

	firstErr := <-errCh
	slog.Debug("reverse: first copy done", "component", "reverse", "target", logTarget, "err", firstErr)

	// If the first copy ended with an error (not clean EOF), the transfer
	// is already broken — no point waiting for the other half to drain.
	// Cancel the stream now so the second goroutine unblocks immediately.
	if firstErr != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}

	done := make(chan struct{})
	go func() { <-errCh; close(done) }()

	timer := time.NewTimer(time.Duration(c.config.QUIC.StreamCloseTimeoutSec) * time.Second)
	defer timer.Stop()

	select {
	case <-done:
		slog.Debug("reverse: stream closed cleanly", "component", "reverse", "target", logTarget)
	case <-timer.C:
		slog.Debug("reverse: stream close timeout, forcing cancel", "component", "reverse", "target", logTarget)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		<-done
	}
}
