package transport

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// tryRecvFunc is one call into a non-blocking recv on a single
// family. Used by dualPollRecv to dispatch v4 vs v6 work.
//
//   - retry=true means "no usable packet this time, keep polling"
//     (EAGAIN, EINTR, malformed packet, source not in peer-spoof set,
//     wrong type/id/etc). Caller continues to the next ready fd or
//     re-polls.
//   - retry=false + err=nil means a real packet was delivered; return
//     n / ip / port to the caller of dualPollRecv.
//   - err != nil means a fatal recv error; abort the entire Receive.
type tryRecvFunc func() (n int, ip net.IP, port uint16, retry bool, err error)

// dualPollRecv runs the icmp / raw transports' "wait on v4 + v6 +
// shutPipe, dispatch to whichever fd is ready" loop. Centralises a
// pattern that was duplicated nearly line-for-line across the two
// transports.
//
// Either or both of recvFd4 / recvFd6 may be -1 (single-stack); the
// matching tryRecv is then never called. shutPipeRd must always be a
// valid read end — the loop returns ErrConnectionClosed on its
// POLLIN.
//
// try4 / try6 must be safe to call only when their respective fd is
// ready (the helper does not pass any state — closures capture the
// fd + peer-spoof set + parsing logic from the calling transport).
func dualPollRecv(recvFd4, recvFd6, shutPipeRd int, try4, try6 tryRecvFunc) (n int, ip net.IP, port uint16, err error) {
	if recvFd4 == -1 && recvFd6 == -1 {
		return 0, nil, 0, errors.New("no receive socket available")
	}

	var pollFds []unix.PollFd
	v4Idx, v6Idx := -1, -1
	if recvFd4 >= 0 {
		v4Idx = len(pollFds)
		pollFds = append(pollFds, unix.PollFd{Fd: int32(recvFd4), Events: unix.POLLIN})
	}
	if recvFd6 >= 0 {
		v6Idx = len(pollFds)
		pollFds = append(pollFds, unix.PollFd{Fd: int32(recvFd6), Events: unix.POLLIN})
	}
	pipeIdx := len(pollFds)
	pollFds = append(pollFds, unix.PollFd{Fd: int32(shutPipeRd), Events: unix.POLLIN})

	for {
		_, perr := unix.Poll(pollFds, -1)
		if perr != nil {
			if perr == syscall.EINTR {
				continue
			}
			if errors.Is(perr, syscall.EBADF) {
				return 0, nil, 0, ErrConnectionClosed
			}
			return 0, nil, 0, fmt.Errorf("poll: %w", perr)
		}
		if pollFds[pipeIdx].Revents&unix.POLLIN != 0 {
			return 0, nil, 0, ErrConnectionClosed
		}

		if v4Idx >= 0 && pollFds[v4Idx].Revents&unix.POLLIN != 0 {
			n, ip, port, retry, rerr := try4()
			if rerr != nil {
				return 0, nil, 0, rerr
			}
			if !retry {
				return n, ip, port, nil
			}
		}
		if v6Idx >= 0 && pollFds[v6Idx].Revents&unix.POLLIN != 0 {
			n, ip, port, retry, rerr := try6()
			if rerr != nil {
				return 0, nil, 0, rerr
			}
			if !retry {
				return n, ip, port, nil
			}
		}
		// Spurious wake or every ready fd produced retry — re-poll.
	}
}
