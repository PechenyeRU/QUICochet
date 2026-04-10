package tunnel

import (
	"log"
)

// In v2.0, Forward and Relay are handled directly by QUIC streams
// inside client.go and server.go.

func (s *Server) startDirectRelayServer() {
	log.Printf("[relay-direct] Direct relay server is disabled in v2.0")
}
