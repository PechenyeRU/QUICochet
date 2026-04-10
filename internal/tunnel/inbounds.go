package tunnel

import (
	"log"
)

// In v2.0, Forward and Relay are handled directly by QUIC streams
// inside client.go and server.go.
// This file is kept for future extensions or helpers.

func (c *Client) startRelayInbound(listenAddr string) error {
	// TODO: Implement UDP relay over QUIC datagrams or streams
	log.Printf("[relay] UDP relay on %s is not yet implemented in v2.0", listenAddr)
	return nil
}

func (c *Client) startDirectRelay(listenAddr string, remotePort int) error {
	// Direct bypass is disabled for now to focus on the core QUIC implementation.
	log.Printf("[relay-direct] Direct relay on %s is disabled in v2.0", listenAddr)
	return nil
}
