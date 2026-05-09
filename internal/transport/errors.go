package transport

import "errors"

var (
	ErrNoSourceIP       = errors.New("no source IP configured")
	ErrConnectionClosed = errors.New("connection closed")
)
