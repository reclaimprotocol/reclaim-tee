package main

import (
	"bufio"
	"context"
	"log"
	"net"
	"strings"
)

// DomainRouter handles routing based on domain
type DomainRouter struct {
	domainMap map[string]RouteTarget // domain -> (CID, port) mapping
}

// RouteTarget represents the target for a domain route
type RouteTarget struct {
	CID            uint32 // Enclave CID
	HttpVsockPort  uint32 // HTTP vsock port
	HttpsVsockPort uint32 // HTTPS vsock port
}

// RouteMapping represents a domain to vsock port mapping
type RouteMapping struct {
	Domain         string
	CID            uint32
	HttpVsockPort  uint32
	HttpsVsockPort uint32
}

// NewDomainRouter creates a new domain router with configuration
func NewDomainRouter() *DomainRouter {
	return &DomainRouter{
		domainMap: make(map[string]RouteTarget),
	}
}

// AddRoute adds a domain routing rule
func (dr *DomainRouter) AddRoute(domain string, cid uint32, httpsPort uint32) {
	target := RouteTarget{
		CID:            cid,
		HttpVsockPort:  httpsPort - 1, // HTTP is one port less than HTTPS
		HttpsVsockPort: httpsPort,
	}
	dr.domainMap[domain] = target
	log.Printf("Added domain route: %s -> CID %d, HTTP port %d, HTTPS port %d",
		domain, cid, target.HttpVsockPort, target.HttpsVsockPort)
}

// GetRouteTarget returns the route target for a domain
func (dr *DomainRouter) GetRouteTarget(domain string) (RouteTarget, bool) {
	target, exists := dr.domainMap[domain]
	return target, exists
}

// GetVsockPort returns the HTTPS vsock port for a domain (for backward compatibility)
func (dr *DomainRouter) GetVsockPort(domain string) (uint32, bool) {
	target, exists := dr.domainMap[domain]
	return target.HttpsVsockPort, exists
}

// RouteHTTPConnection routes HTTP connections and returns the target
func (dr *DomainRouter) RouteHTTPConnection(ctx context.Context, clientConn net.Conn) RouteTarget {
	// Peek at the first line to get the Host header
	reader := bufio.NewReader(clientConn)

	// Read the request line and headers to find Host
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			log.Printf("Error reading HTTP request: %v", err)
			// Return default TEE_K target
			return RouteTarget{CID: 16, HttpVsockPort: 8000, HttpsVsockPort: 8001}
		}

		lineStr := string(line)
		if strings.HasPrefix(strings.ToLower(lineStr), "host:") {
			host := strings.TrimSpace(strings.TrimPrefix(lineStr, "Host:"))
			host = strings.TrimSpace(strings.TrimPrefix(host, "host:"))

			// Remove port if present
			if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
				host = host[:colonIndex]
			}

			// Look up route target
			if target, exists := dr.GetRouteTarget(host); exists {
				log.Printf("Routed HTTP request for %s to CID %d port %d", host, target.CID, target.HttpVsockPort)
				return target
			}
			break
		}

		// Empty line indicates end of headers
		if len(line) == 0 {
			break
		}
	}

	log.Printf("No route found for HTTP request, using default TEE_K target")
	return RouteTarget{CID: 16, HttpVsockPort: 8000, HttpsVsockPort: 8001}
}

// SNIExtractor extracts SNI from TLS ClientHello
type SNIExtractor struct{}

// ExtractSNI extracts the Server Name Indication from a TLS ClientHello
func (se *SNIExtractor) ExtractSNI(data []byte) string {
	if len(data) < 6 {
		return ""
	}

	// Check if this is a TLS handshake record
	if data[0] != 0x16 { // TLS Handshake
		return ""
	}

	// Skip TLS record header (5 bytes)
	pos := 5
	if pos >= len(data) {
		return ""
	}

	// Check if this is a ClientHello (0x01)
	if data[pos] != 0x01 {
		return ""
	}

	// Skip handshake header (4 bytes)
	pos += 4
	if pos+2 >= len(data) {
		return ""
	}

	// Skip client version (2 bytes)
	pos += 2

	// Skip client random (32 bytes)
	pos += 32
	if pos >= len(data) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 >= len(data) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos >= len(data) {
		return ""
	}

	// Skip compression methods
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen
	if pos+2 >= len(data) {
		return ""
	}

	// Extensions length
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	// Parse extensions
	endPos := pos + extensionsLen
	for pos < endPos && pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0x00 { // SNI extension
			return se.parseSNIExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return ""
}

func (se *SNIExtractor) parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Skip server name list length (2 bytes)
	pos := 2
	if pos >= len(data) {
		return ""
	}

	// Parse server names
	for pos < len(data) {
		if pos+3 >= len(data) {
			break
		}

		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if nameType == 0x00 && pos+nameLen <= len(data) { // hostname
			return string(data[pos : pos+nameLen])
		}

		pos += nameLen
	}

	return ""
}

// ConnectionRouter handles the actual routing with SNI inspection
type ConnectionRouter struct {
	domainRouter *DomainRouter
	sniExtractor *SNIExtractor
}

// NewConnectionRouter creates a new connection router
func NewConnectionRouter(domainRouter *DomainRouter) *ConnectionRouter {
	return &ConnectionRouter{
		domainRouter: domainRouter,
		sniExtractor: &SNIExtractor{},
	}
}

// RouteHTTPSConnection routes HTTPS connections based on SNI and returns target and wrapped connection
func (cr *ConnectionRouter) RouteHTTPSConnection(ctx context.Context, clientConn net.Conn) (RouteTarget, net.Conn) {
	// Peek at the first packet to extract SNI
	buffer := make([]byte, 4096)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Printf("Error reading from client connection: %v", err)
		defaultTarget := RouteTarget{CID: 16, HttpVsockPort: 8000, HttpsVsockPort: 8001}
		return defaultTarget, clientConn // fallback
	}

	// Extract SNI from TLS ClientHello
	sni := cr.sniExtractor.ExtractSNI(buffer[:n])
	if sni != "" {
		if target, exists := cr.domainRouter.GetRouteTarget(sni); exists {
			log.Printf("Routed HTTPS connection for %s to CID %d port %d", sni, target.CID, target.HttpsVsockPort)

			// Create a new connection that includes the peeked data
			wrappedConn := &BufferedConnection{
				Conn:   clientConn,
				buffer: buffer[:n],
			}

			return target, wrappedConn
		}
	}

	log.Printf("No SNI found or no route for domain %s, using default TEE_K target", sni)

	// Still need to replay the buffered data for the default case
	wrappedConn := &BufferedConnection{
		Conn:   clientConn,
		buffer: buffer[:n],
	}

	defaultTarget := RouteTarget{CID: 16, HttpVsockPort: 8000, HttpsVsockPort: 8001}
	return defaultTarget, wrappedConn
}

// BufferedConnection wraps a connection to replay buffered data
type BufferedConnection struct {
	net.Conn
	buffer     []byte
	bufferRead bool
}

func (bc *BufferedConnection) Read(b []byte) (n int, err error) {
	if !bc.bufferRead && len(bc.buffer) > 0 {
		n = copy(b, bc.buffer)
		if n < len(bc.buffer) {
			bc.buffer = bc.buffer[n:]
		} else {
			bc.bufferRead = true
		}
		return n, nil
	}
	return bc.Conn.Read(b)
}

// HTTPSConnectionReader helps read TLS data without consuming it
type HTTPSConnectionReader struct {
	conn   net.Conn
	buffer []byte
	read   bool
}

// NewHTTPSConnectionReader creates a new HTTPS connection reader
func NewHTTPSConnectionReader(conn net.Conn) *HTTPSConnectionReader {
	return &HTTPSConnectionReader{
		conn: conn,
	}
}

// PeekSNI peeks at the connection to extract SNI without consuming data
func (hcr *HTTPSConnectionReader) PeekSNI() (string, net.Conn, error) {
	if !hcr.read {
		buffer := make([]byte, 4096)
		n, err := hcr.conn.Read(buffer)
		if err != nil {
			return "", hcr.conn, err
		}
		hcr.buffer = buffer[:n]
		hcr.read = true
	}

	extractor := &SNIExtractor{}
	sni := extractor.ExtractSNI(hcr.buffer)

	// Create a connection that will replay the buffered data
	wrappedConn := &ReplayConnection{
		Conn:   hcr.conn,
		buffer: hcr.buffer,
	}

	return sni, wrappedConn, nil
}

// ReplayConnection replays buffered data then continues with normal reads
type ReplayConnection struct {
	net.Conn
	buffer   []byte
	replayed bool
}

func (rc *ReplayConnection) Read(b []byte) (n int, err error) {
	if !rc.replayed && len(rc.buffer) > 0 {
		n = copy(b, rc.buffer)
		if n >= len(rc.buffer) {
			rc.replayed = true
		} else {
			rc.buffer = rc.buffer[n:]
		}
		return n, nil
	}
	return rc.Conn.Read(b)
}
