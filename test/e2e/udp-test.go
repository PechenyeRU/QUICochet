// UDP ASSOCIATE test tool — sends a DNS query through SOCKS5 UDP ASSOCIATE
// and verifies the response. Tests the full UDP relay path.
//
// Usage: go run udp-test.go [socks5-addr] [dns-server] [domain]
// Example: go run udp-test.go 127.0.0.1:1080 1.1.1.1:53 example.com
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	socksAddr := "127.0.0.1:1080"
	dnsServer := "1.1.1.1:53"
	domain := "example.com"

	if len(os.Args) > 1 {
		socksAddr = os.Args[1]
	}
	if len(os.Args) > 2 {
		dnsServer = os.Args[2]
	}
	if len(os.Args) > 3 {
		domain = os.Args[3]
	}

	fmt.Printf("SOCKS5 UDP ASSOCIATE test\n")
	fmt.Printf("  proxy:  %s\n", socksAddr)
	fmt.Printf("  dns:    %s\n", dnsServer)
	fmt.Printf("  domain: %s\n\n", domain)

	// Step 1: TCP control connection + auth + UDP ASSOCIATE
	fmt.Print("[1] TCP connect to SOCKS5... ")
	tcpConn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	defer tcpConn.Close()
	fmt.Println("OK")

	// Auth: version 5, 1 method, no-auth
	fmt.Print("[2] Auth negotiation... ")
	tcpConn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	if _, err := tcpConn.Read(authResp); err != nil || authResp[1] != 0x00 {
		fmt.Printf("FAIL: %v (resp: %x)\n", err, authResp)
		os.Exit(1)
	}
	fmt.Println("OK")

	// UDP ASSOCIATE: CMD=0x03, ATYP=0x01, ADDR=0.0.0.0, PORT=0
	fmt.Print("[3] UDP ASSOCIATE request... ")
	tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	assocResp := make([]byte, 10)
	if _, err := tcpConn.Read(assocResp); err != nil {
		fmt.Printf("FAIL: read: %v\n", err)
		os.Exit(1)
	}
	if assocResp[1] != 0x00 {
		fmt.Printf("FAIL: reply code %d\n", assocResp[1])
		os.Exit(1)
	}

	// Parse BND.ADDR:BND.PORT from reply
	bindIP := net.IP(assocResp[4:8])
	bindPort := binary.BigEndian.Uint16(assocResp[8:10])
	if bindIP.Equal(net.IPv4zero) {
		// Use proxy's TCP address
		bindIP = tcpConn.RemoteAddr().(*net.TCPAddr).IP
	}
	relayAddr := &net.UDPAddr{IP: bindIP, Port: int(bindPort)}
	fmt.Printf("OK (relay: %s)\n", relayAddr)

	// Step 2: Open local UDP socket
	fmt.Print("[4] Open UDP socket... ")
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	defer udpConn.Close()
	fmt.Println("OK")

	// Step 3: Build DNS query
	dnsHost, dnsPortStr, _ := net.SplitHostPort(dnsServer)
	dnsPort := uint16(53)
	if p, err := net.LookupPort("udp", dnsPortStr); err == nil {
		dnsPort = uint16(p)
	}

	dnsQuery := buildDNSQuery(domain)

	// Build SOCKS5 UDP header: [RSV:2][FRAG:1][ATYP][ADDR][PORT][DATA]
	dnsIP := net.ParseIP(dnsHost)
	var addrBytes []byte
	if dnsIP != nil && dnsIP.To4() != nil {
		addrBytes = make([]byte, 7)
		addrBytes[0] = 0x01 // IPv4
		copy(addrBytes[1:5], dnsIP.To4())
		binary.BigEndian.PutUint16(addrBytes[5:7], dnsPort)
	} else {
		// Domain
		addrBytes = make([]byte, 2+len(dnsHost)+2)
		addrBytes[0] = 0x03
		addrBytes[1] = byte(len(dnsHost))
		copy(addrBytes[2:], dnsHost)
		binary.BigEndian.PutUint16(addrBytes[2+len(dnsHost):], dnsPort)
	}

	pkt := make([]byte, 3+len(addrBytes)+len(dnsQuery))
	// RSV=0, FRAG=0
	copy(pkt[3:], addrBytes)
	copy(pkt[3+len(addrBytes):], dnsQuery)

	// Step 4: Send DNS query via relay
	fmt.Print("[5] Send DNS query via UDP relay... ")
	_, err = udpConn.WriteToUDP(pkt, relayAddr)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	// Step 5: Receive response
	fmt.Print("[6] Receive DNS response... ")
	udpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	respBuf := make([]byte, 4096)
	n, _, err := udpConn.ReadFromUDP(respBuf)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}

	// Strip SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP + ADDR + PORT
	if n < 3 {
		fmt.Printf("FAIL: response too short (%d bytes)\n", n)
		os.Exit(1)
	}
	offset := 3 // skip RSV + FRAG
	atyp := respBuf[offset]
	offset++
	switch atyp {
	case 0x01:
		offset += 4 + 2 // IPv4 + port
	case 0x04:
		offset += 16 + 2 // IPv6 + port
	case 0x03:
		dLen := int(respBuf[offset])
		offset += 1 + dLen + 2
	}

	if offset >= n {
		fmt.Printf("FAIL: no payload after SOCKS5 header\n")
		os.Exit(1)
	}

	dnsResp := respBuf[offset:n]
	fmt.Printf("OK (%d bytes DNS response)\n", len(dnsResp))

	// Parse DNS response for A records
	fmt.Print("[7] Parse DNS response... ")
	ips := parseDNSResponse(dnsResp)
	if len(ips) == 0 {
		fmt.Println("FAIL: no A records found")
		os.Exit(1)
	}
	fmt.Printf("OK → %s resolves to %v\n", domain, ips)

	fmt.Println("\n=== ALL TESTS PASSED ===")
	fmt.Println("UDP ASSOCIATE → QUIC datagram → DNS relay works correctly")
}

// buildDNSQuery builds a minimal DNS A record query
func buildDNSQuery(domain string) []byte {
	buf := make([]byte, 0, 512)

	// Header: ID=0x1234, flags=0x0100 (standard query, recursion desired)
	buf = append(buf, 0x12, 0x34, 0x01, 0x00)
	buf = append(buf, 0x00, 0x01) // QDCOUNT=1
	buf = append(buf, 0x00, 0x00) // ANCOUNT=0
	buf = append(buf, 0x00, 0x00) // NSCOUNT=0
	buf = append(buf, 0x00, 0x00) // ARCOUNT=0

	// Question: domain name in DNS format
	for len(domain) > 0 {
		dot := len(domain)
		for i := 0; i < len(domain); i++ {
			if domain[i] == '.' {
				dot = i
				break
			}
		}
		buf = append(buf, byte(dot))
		buf = append(buf, domain[:dot]...)
		if dot < len(domain) {
			domain = domain[dot+1:]
		} else {
			domain = ""
		}
	}
	buf = append(buf, 0x00) // root label

	buf = append(buf, 0x00, 0x01) // QTYPE=A
	buf = append(buf, 0x00, 0x01) // QCLASS=IN

	return buf
}

// parseDNSResponse extracts A record IPs from a DNS response
func parseDNSResponse(data []byte) []string {
	if len(data) < 12 {
		return nil
	}

	// Skip header (12 bytes)
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	ancount := int(binary.BigEndian.Uint16(data[6:8]))

	// Skip questions
	for i := 0; i < qdcount && offset < len(data); i++ {
		for offset < len(data) {
			l := int(data[offset])
			if l == 0 {
				offset++
				break
			}
			if l >= 0xC0 { // pointer
				offset += 2
				break
			}
			offset += 1 + l
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answers
	var ips []string
	for i := 0; i < ancount && offset+12 <= len(data); i++ {
		// Skip name (might be pointer)
		if offset < len(data) && data[offset] >= 0xC0 {
			offset += 2
		} else {
			for offset < len(data) {
				l := int(data[offset])
				if l == 0 {
					offset++
					break
				}
				offset += 1 + l
			}
		}

		if offset+10 > len(data) {
			break
		}
		rtype := binary.BigEndian.Uint16(data[offset:])
		offset += 2 // TYPE
		offset += 2 // CLASS
		offset += 4 // TTL
		rdlen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2

		if rtype == 1 && rdlen == 4 && offset+4 <= len(data) {
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			ips = append(ips, ip.String())
		}
		offset += rdlen
	}

	return ips
}
