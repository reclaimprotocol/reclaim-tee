package client

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func incrementalTestWebSocket(t *testing.T, receive func(*teeproto.Envelope)) *websocket.Conn {
	t.Helper()
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var env teeproto.Envelope
			if err := proto.Unmarshal(data, &env); err != nil {
				t.Error(err)
				return
			}
			receive(&env)
		}
	}))
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type incrementalScriptConn struct {
	responseScriptConn
	onRead func()
}

func (c *incrementalScriptConn) Read(p []byte) (int, error) {
	if c.onRead != nil {
		c.onRead()
	}
	return c.responseScriptConn.Read(p)
}

func TestIncrementalTCPHandshakeOnlyThenDelayedHTTP(t *testing.T) {
	for _, lastErr := range []error{nil, io.EOF, idleTimeoutTestError{}} {
		t.Run(fmtSprintError(lastErr), func(t *testing.T) {
			c := newIncrementalTestClient(t)
			finalized := make(chan *teeproto.FinalizeResponse, 1)
			redacted := make(chan struct{}, 1)
			c.wsConn = incrementalTestWebSocket(t, func(env *teeproto.Envelope) {
				if ready := env.GetResponseCaptureReady(); ready != nil {
					if err := c.receiveResponseCaptureReady(c.sessionID, &teeproto.ResponseCaptureReady{SessionBinding: ready.SessionBinding, Acknowledged: true}); err != nil {
						t.Error(err)
					}
				}
				if f := env.GetFinalizeResponse(); f != nil {
					finalized <- f
				}
				if env.GetResponseRedactionSpec() != nil {
					redacted <- struct{}{}
				}
			})
			c.teetConn = incrementalTestWebSocket(t, func(env *teeproto.Envelope) {
				b := env.GetBatchedEncryptedResponses()
				if b == nil {
					t.Error("unexpected message to TEE_T")
					return
				}
				d := &teeproto.BatchedDecryptionStreams{SessionId: c.sessionID, Metadata: proto.Clone(b.Metadata).(*teeproto.ResponseBatchMetadata), TotalCount: b.TotalCount}
				for _, r := range b.Responses {
					d.DecryptionStreams = append(d.DecryptionStreams, &teeproto.ResponseDecryptionStreamData{SeqNum: r.SeqNum, Length: int32(len(r.EncryptedData)), DecryptionStream: make([]byte, len(r.EncryptedData))})
				}
				if err := c.receiveIncrementalDecryption(c.sessionID, d); err != nil {
					t.Error(err)
					c.terminateConnectionWithError("test decryption", err)
				}
			})
			t.Cleanup(c.Close)
			wire := func(r shared.EncryptedResponseData) []byte {
				return bytes.Join([][]byte{r.RecordHeader, r.EncryptedData, r.Tag}, nil)
			}
			tickets := append(wire(incrementalTestRecord(0, []byte{4, 0, 0, 0}, 22)), wire(incrementalTestRecord(1, []byte{4, 0, 0, 0}, 22))...)
			response := wire(incrementalTestRecord(2, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"), 23))
			conn := &incrementalScriptConn{responseScriptConn: responseScriptConn{steps: []responseRead{{data: tickets}}}}
			for range 6 {
				conn.steps = append(conn.steps, responseRead{err: idleTimeoutTestError{}})
			}
			conn.steps = append(conn.steps, responseRead{data: response, err: lastErr})
			conn.onRead = func() {
				if conn.next >= 1 && conn.next <= 7 {
					if c.incrementalResponse.recordCount != 2 || c.incrementalResponse.framer.Complete() || c.responseReconstructed {
						t.Error("handshake-only traffic was treated as HTTP completion")
					}
				}
			}
			c.tcpConn = conn
			done := make(chan struct{})
			go func() { c.tcpToWebsocket(); close(done) }()
			var freeze *teeproto.FinalizeResponse
			select {
			case freeze = <-finalized:
			case <-time.After(5 * time.Second):
				t.Fatal("response did not request freeze")
			}
			if freeze.BatchCount != 3 || freeze.RecordCount != 3 {
				t.Fatalf("unexpected frozen prefix: %v", freeze)
			}
			if c.responseReconstructed {
				t.Fatal("reconstruction preceded freeze acknowledgment")
			}
			select {
			case <-redacted:
				t.Fatal("redaction preceded freeze acknowledgment")
			default:
			}
			if err := c.receiveResponseFrozen(c.sessionID, &teeproto.ResponseFrozen{SessionBinding: freeze.SessionBinding, BatchCount: freeze.BatchCount, RecordCount: freeze.RecordCount, PrefixCommitment: freeze.PrefixCommitment}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("capture did not finish after freeze")
			}
			if !c.responseReconstructed || c.expectedRedactedStreams != 3 || conn.next != len(conn.steps) {
				t.Fatal("incomplete final response state")
			}
			select {
			case <-redacted:
			case <-time.After(time.Second):
				t.Fatal("redaction not sent after freeze")
			}
		})
	}
}

func fmtSprintError(err error) string {
	if err == nil {
		return "without EOF"
	}
	return err.Error()
}

func TestIncrementalAuthenticationWaitIsBoundedByWatchdog(t *testing.T) {
	c := newIncrementalTestClient(t)
	c.wsConn = incrementalTestWebSocket(t, func(env *teeproto.Envelope) {
		if ready := env.GetResponseCaptureReady(); ready != nil {
			if err := c.receiveResponseCaptureReady(c.sessionID, &teeproto.ResponseCaptureReady{SessionBinding: ready.SessionBinding, Acknowledged: true}); err != nil {
				t.Error(err)
			}
		}
	})
	c.teetConn = incrementalTestWebSocket(t, func(*teeproto.Envelope) {})
	t.Cleanup(c.Close)
	record := incrementalTestRecord(0, []byte{4, 0, 0, 0}, 22)
	c.tcpConn = &responseScriptConn{steps: []responseRead{{data: bytes.Join([][]byte{record.RecordHeader, record.EncryptedData, record.Tag}, nil)}}}
	c.coreProtocolTimeout = 20 * time.Millisecond
	done := make(chan struct{})
	go func() { c.tcpToWebsocket(); close(done) }()
	c.startCoreProtocolWatchdog()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("authentication wait outlived watchdog")
	}
	if c.responseReconstructed {
		t.Fatal("timed-out batch reconstructed response")
	}
	select {
	case err := <-c.WaitForCompletion():
		if err == nil {
			t.Fatal("watchdog reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog did not publish failure")
	}
}

func newIncrementalTestClient(t *testing.T) *Client {
	t.Helper()
	c := NewClient("")
	c.sessionID = "incremental-test-session"
	c.requestData = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	c.cipherSuite = 0x1301
	if err := c.configureResponseMode(shared.HandshakeCompleteData{CipherSuite: c.cipherSuite, SelectedResponseMode: teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1, ResponseBinding: bytes.Repeat([]byte{7}, 32)}); err != nil {
		t.Fatal(err)
	}
	c.handshakeComplete.Store(true)
	c.httpRequestSent.Store(true)
	return c
}

func incrementalTestRecord(seq uint64, content []byte, contentType byte) shared.EncryptedResponseData {
	plaintext := append(bytes.Clone(content), contentType)
	length := len(plaintext) + 16
	return shared.EncryptedResponseData{SeqNum: seq, EncryptedData: plaintext, Tag: make([]byte, 16), RecordHeader: []byte{23, 3, 3, byte(length >> 8), byte(length)}}
}

func incrementalTestStreams(t *testing.T, c *Client, records []shared.EncryptedResponseData) *teeproto.BatchedDecryptionStreams {
	t.Helper()
	s := c.incrementalResponse
	metadata, err := shared.BuildResponseBatchMetadata(c.sessionID, s.binding, s.prefix, s.batchCount, s.recordCount, records)
	if err != nil {
		t.Fatal(err)
	}
	batch := &teeproto.BatchedDecryptionStreams{SessionId: c.sessionID, TotalCount: int32(len(records)), Metadata: metadata}
	for _, record := range records {
		batch.DecryptionStreams = append(batch.DecryptionStreams, &teeproto.ResponseDecryptionStreamData{SeqNum: record.SeqNum, Length: int32(len(record.EncryptedData)), DecryptionStream: make([]byte, len(record.EncryptedData))})
	}
	s.pending = proto.Clone(metadata).(*teeproto.ResponseBatchMetadata)
	s.pendingRecords = records
	return batch
}

func TestIncrementalModeNegotiation(t *testing.T) {
	for _, mode := range []string{"", "incremental", "legacy"} {
		if _, err := parseResponseMode(mode); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := parseResponseMode("future"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	c := NewClient("")
	if err := c.configureResponseMode(shared.HandshakeCompleteData{}); err != nil {
		t.Fatal(err)
	}
	c.handshakeComplete.Store(true)
	if c.SelectedResponseMode() != teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF {
		t.Fatal("missing field did not select legacy")
	}
	for _, data := range []shared.HandshakeCompleteData{
		{SelectedResponseMode: teeproto.ResponseMode(99)},
		{ResponseBinding: make([]byte, 32)},
		{SelectedResponseMode: teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1, CipherSuite: 0x1301, ResponseBinding: []byte{1}},
		{SelectedResponseMode: teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1, CipherSuite: 0xc013, ResponseBinding: make([]byte, 32)},
	} {
		if err := NewClient("").configureResponseMode(data); err == nil {
			t.Fatalf("invalid negotiation accepted: %+v", data)
		}
	}
	legacy := NewClient("")
	legacy.requestedResponseMode = teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF
	if err := legacy.configureResponseMode(shared.HandshakeCompleteData{SelectedResponseMode: teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1, CipherSuite: 0x1301, ResponseBinding: make([]byte, 32)}); err == nil {
		t.Fatal("unrequested mode accepted")
	}
}

func TestIncrementalDecryptionRejectsInvalidBatchBeforeMutation(t *testing.T) {
	mutations := map[string]func(*teeproto.BatchedDecryptionStreams){
		"session":      func(b *teeproto.BatchedDecryptionStreams) { b.SessionId = "other" },
		"metadata":     func(b *teeproto.BatchedDecryptionStreams) { b.Metadata.BatchId++ },
		"prefix":       func(b *teeproto.BatchedDecryptionStreams) { b.Metadata.PrefixCommitment[0] ^= 1 },
		"count":        func(b *teeproto.BatchedDecryptionStreams) { b.TotalCount++ },
		"missing":      func(b *teeproto.BatchedDecryptionStreams) { b.DecryptionStreams = nil },
		"sequence":     func(b *teeproto.BatchedDecryptionStreams) { b.DecryptionStreams[0].SeqNum++ },
		"short stream": func(b *teeproto.BatchedDecryptionStreams) { b.DecryptionStreams[0].DecryptionStream = nil },
		"length":       func(b *teeproto.BatchedDecryptionStreams) { b.DecryptionStreams[0].Length++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := newIncrementalTestClient(t)
			record := incrementalTestRecord(0, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 23)
			c.ciphertextBySeq[0] = bytes.Clone(record.EncryptedData)
			batch := incrementalTestStreams(t, c, []shared.EncryptedResponseData{record})
			mutate(batch)
			if err := c.receiveIncrementalDecryption(c.sessionID, batch); err == nil {
				t.Fatal("invalid batch accepted")
			}
			if len(c.parsedResponseBySeq) != 0 || !bytes.Equal(c.ciphertextBySeq[0], record.EncryptedData) {
				t.Fatal("invalid batch mutated response maps")
			}
		})
	}
}

func TestIncrementalHandshakeThenHTTPAndDuplicate(t *testing.T) {
	c := newIncrementalTestClient(t)
	records := []shared.EncryptedResponseData{incrementalTestRecord(0, []byte{4, 0, 0, 0}, 22), incrementalTestRecord(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"), 23)}
	for _, record := range records {
		c.ciphertextBySeq[record.SeqNum] = bytes.Clone(record.EncryptedData)
	}
	batch := incrementalTestStreams(t, c, records)
	if err := c.receiveIncrementalDecryption(c.sessionID, batch); err != nil {
		t.Fatal(err)
	}
	if err := c.receiveIncrementalDecryption(c.sessionID, batch); err == nil {
		t.Fatal("duplicate batch accepted")
	}
	if err := c.decryptIncrementalBatch(records, <-c.incrementalResponse.streams); err != nil {
		t.Fatal(err)
	}
	if !c.incrementalResponse.framer.Complete() {
		t.Fatal("authenticated HTTP not complete")
	}
	if c.responseReconstructed {
		t.Fatal("reconstruction preceded freeze")
	}
	if got := len(c.ciphertextBySeq[0]); got != len(records[0].EncryptedData)-1 {
		t.Fatalf("ciphertext length %d", got)
	}
}

func TestIncrementalFreezeMatchesExactPrefixOnce(t *testing.T) {
	c := newIncrementalTestClient(t)
	s := c.incrementalResponse
	s.finalize = &teeproto.FinalizeResponse{SessionBinding: bytes.Clone(s.binding), BatchCount: 2, RecordCount: 3, PrefixCommitment: bytes.Clone(s.prefix)}
	f := &teeproto.ResponseFrozen{SessionBinding: bytes.Clone(s.binding), BatchCount: 2, RecordCount: 3, PrefixCommitment: bytes.Clone(s.prefix)}
	bad := proto.Clone(f).(*teeproto.ResponseFrozen)
	bad.RecordCount++
	if err := c.receiveResponseFrozen(c.sessionID, bad); err == nil {
		t.Fatal("different prefix accepted")
	}
	if err := c.receiveResponseFrozen(c.sessionID, f); err != nil {
		t.Fatal(err)
	}
	if err := c.receiveResponseFrozen(c.sessionID, f); err == nil {
		t.Fatal("duplicate freeze accepted")
	}
	if c.responseReconstructed {
		t.Fatal("WebSocket reader reconstructed response")
	}
}

func TestIncrementalCaptureBarrierRejectsWrongAcknowledgments(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		session                 string
		requested, acknowledged bool
		binding                 []byte
	}{
		{name: "unsolicited", session: "incremental-test-session", acknowledged: true, binding: bytes.Repeat([]byte{7}, 32)},
		{name: "wrong session", session: "other", requested: true, acknowledged: true, binding: bytes.Repeat([]byte{7}, 32)},
		{name: "wrong direction", session: "incremental-test-session", requested: true, binding: bytes.Repeat([]byte{7}, 32)},
		{name: "wrong binding", session: "incremental-test-session", requested: true, acknowledged: true, binding: bytes.Repeat([]byte{8}, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newIncrementalTestClient(t)
			c.incrementalResponse.captureRequested = tc.requested
			if err := c.receiveResponseCaptureReady(tc.session, &teeproto.ResponseCaptureReady{SessionBinding: tc.binding, Acknowledged: tc.acknowledged}); err == nil {
				t.Fatal("invalid capture acknowledgment accepted")
			}
			if c.incrementalResponse.captureAcknowledged {
				t.Fatal("invalid acknowledgment changed capture state")
			}
		})
	}
	c := newIncrementalTestClient(t)
	c.incrementalResponse.captureRequested = true
	ready := &teeproto.ResponseCaptureReady{SessionBinding: bytes.Clone(c.incrementalResponse.binding), Acknowledged: true}
	if err := c.receiveResponseCaptureReady(c.sessionID, ready); err != nil {
		t.Fatal(err)
	}
	if err := c.receiveResponseCaptureReady(c.sessionID, ready); err == nil {
		t.Fatal("duplicate capture acknowledgment accepted")
	}
	legacy := NewClient("")
	legacy.handshakeComplete.Store(true)
	if err := legacy.receiveResponseCaptureReady("", ready); err == nil {
		t.Fatal("legacy mode accepted capture acknowledgment")
	}
}

// The K connection deliberately stops while processing an earlier TCPData
// message. The response can reach T only after K processes that message and
// acknowledges the subsequent capture marker on the same ordered connection.
func TestIncrementalCaptureBarrierOrdersHandshakeForwarding(t *testing.T) {
	c := newIncrementalTestClient(t)
	priorReceived := make(chan struct{})
	releasePrior := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releasePrior) }) }
	defer release()
	markerReceived := make(chan *teeproto.ResponseCaptureReady, 1)
	batchReceived := make(chan *teeproto.BatchedEncryptedResponses, 1)
	c.wsConn = incrementalTestWebSocket(t, func(env *teeproto.Envelope) {
		if env.GetTcpData() != nil {
			close(priorReceived)
			<-releasePrior
		}
		if marker := env.GetResponseCaptureReady(); marker != nil {
			markerReceived <- marker
		}
	})
	c.teetConn = incrementalTestWebSocket(t, func(env *teeproto.Envelope) {
		if batch := env.GetBatchedEncryptedResponses(); batch != nil {
			batchReceived <- batch
		}
	})
	t.Cleanup(c.Close)
	record := incrementalTestRecord(0, []byte{4, 0, 0, 0}, 22)
	c.batchedResponses = []shared.EncryptedResponseData{record}
	c.ciphertextBySeq[0] = bytes.Clone(record.EncryptedData)
	done := make(chan error, 1)
	go func() {
		if err := c.sendEnvelope(&teeproto.Envelope{Payload: &teeproto.Envelope_TcpData{TcpData: &teeproto.TCPData{Data: []byte("earlier handshake forwarding")}}}); err != nil {
			done <- err
			return
		}
		done <- c.authenticateIncrementalBatch()
	}()
	select {
	case <-priorReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("K did not receive earlier forwarding")
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		c.incrementalResponse.mu.Lock()
		requested := c.incrementalResponse.captureRequested
		c.incrementalResponse.mu.Unlock()
		if requested {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("TCP owner did not request capture barrier")
		case <-tick.C:
		}
	}
	select {
	case <-batchReceived:
		t.Fatal("response batch overtook unprocessed handshake forwarding")
	default:
	}
	release()
	var marker *teeproto.ResponseCaptureReady
	select {
	case marker = <-markerReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("capture marker missing after earlier forwarding")
	}
	if marker.Acknowledged {
		t.Fatal("client sent an acknowledgment instead of a request")
	}
	select {
	case <-batchReceived:
		t.Fatal("response batch preceded capture acknowledgment")
	default:
	}
	if err := c.receiveResponseCaptureReady(c.sessionID, &teeproto.ResponseCaptureReady{SessionBinding: marker.SessionBinding, Acknowledged: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-batchReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("acknowledged barrier did not release batch")
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("response wait did not stop on close")
	}
}

func TestIncrementalCaptureBarrierWaitIsBoundedByWatchdog(t *testing.T) {
	c := newIncrementalTestClient(t)
	c.wsConn = incrementalTestWebSocket(t, func(*teeproto.Envelope) {})
	t.Cleanup(c.Close)
	c.coreProtocolTimeout = 20 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- c.establishResponseCapture() }()
	c.startCoreProtocolWatchdog()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("capture barrier succeeded without acknowledgment")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture barrier outlived watchdog")
	}
}
