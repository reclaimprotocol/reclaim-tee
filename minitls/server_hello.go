package minitls

type ServerHelloMsg struct {
	vers                 uint16
	random               []byte
	sessionId            []byte
	cipherSuite          uint16
	compressionMethod    uint8
	supportedVersion     uint16
	serverShare          keyShare
	preSharedKeyIdentity uint16
}

type keyShare struct {
	group uint16
	data  []byte
}
