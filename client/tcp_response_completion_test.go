package client

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"google.golang.org/protobuf/proto"
)

type responseRead struct {
	data []byte
	err  error
}
type responseScriptConn struct {
	idleTimeoutTestConn
	steps []responseRead
	next  int
}

func (c *responseScriptConn) Read(p []byte) (int, error) {
	if c.next == len(c.steps) {
		return 0, io.EOF
	}
	s := c.steps[c.next]
	c.next++
	return copy(p, s.data), s.err
}

// The capture client cannot decrypt these opaque TLS 1.3 records. In the
// incident the first two records decrypted to Handshake, despite outer type 23.
func TestTCPResponseWaitsForEOFDespiteIdleRecords(t *testing.T) {
	tickets := bytes.Join(makeRecords(0x41, 2, 314), nil)
	response := bytes.Join(makeRecords(0x42, 2, 256), nil)
	for _, tc := range []struct {
		name          string
		before, after []byte
		readErr       error
	}{
		{"post_handshake_before_delayed_HTTP", tickets, response, io.EOF},
		{"pause_mid_HTTP_response", append(append([]byte{}, tickets...), response[:261]...), response[261:], io.EOF},
		{"pause_mid_TLS_record", append(append([]byte{}, tickets...), response[:100]...), response[100:], io.EOF},
		{"data_with_timeout", tickets, response, idleTimeoutTestError{}},
		{"partial_record_with_timeout", append(append([]byte{}, tickets...), response[:100]...), response[100:], idleTimeoutTestError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan []byte, 1)
			upgrader := websocket.Upgrader{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				_, data, err := conn.ReadMessage()
				if err == nil {
					received <- data
				}
			}))
			defer server.Close()
			ws, _, err := websocket.DefaultDialer.Dial(wsURL(server.URL), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			c := NewClient("")
			c.teetConn = ws
			c.cipherSuite = 0x1301
			c.handshakeComplete.Store(true)
			c.httpRequestSent.Store(true)
			conn := &responseScriptConn{steps: []responseRead{{data: tc.before}}}
			for i := 0; i < 6; i++ {
				conn.steps = append(conn.steps, responseRead{err: idleTimeoutTestError{}})
			}
			// Exercise bytes returned with EOF or a timeout, followed by real EOF.
			conn.steps = append(conn.steps, responseRead{data: tc.after, err: tc.readErr})
			if tc.readErr != io.EOF {
				conn.steps = append(conn.steps, responseRead{err: io.EOF})
			}
			c.tcpConn = conn
			c.tcpToWebsocket()
			if conn.next != len(conn.steps) {
				t.Fatalf("stopped after %d/%d reads, before delayed HTTP/EOF", conn.next, len(conn.steps))
			}
			select {
			case data := <-received:
				var env teeproto.Envelope
				if err := proto.Unmarshal(data, &env); err != nil {
					t.Fatal(err)
				}
				batch := env.GetBatchedEncryptedResponses()
				if batch == nil || len(batch.Responses) != 4 {
					t.Fatalf("want all four records, got %v", batch)
				}
				expected := append(makeRecords(0x41, 2, 314), makeRecords(0x42, 2, 256)...)
				for i, r := range batch.Responses {
					wire := append(append(append([]byte{}, r.RecordHeader...), r.EncryptedData...), r.Tag...)
					if r.SeqNum != uint64(i) || !bytes.Equal(wire, expected[i]) {
						t.Fatalf("record %d corrupted or out of order", i)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("EOF did not flush response")
			}
		})
	}
}

// A peer ignoring Connection: close must remain bounded. The watchdog must unblock the actual TCP reader, not just signal an
// error to the caller.
func TestTCPResponseWithoutEOFIsBoundedByCoreWatchdog(t *testing.T) {
	c := NewClient("")
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	c.tcpConn = conn
	c.handshakeComplete.Store(true)
	c.httpRequestSent.Store(true)
	c.coreProtocolTimeout = 20 * time.Millisecond
	done := make(chan struct{})
	go func() { c.tcpToWebsocket(); close(done) }()
	c.startCoreProtocolWatchdog()
	select {
	case err := <-c.WaitForCompletion():
		if err == nil || !strings.Contains(err.Error(), "core TEE protocol timed out") {
			t.Fatalf("completion = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("core deadline did not bound a peer without EOF")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not stop TCP capture")
	}
}

func TestTCPHandshakeStallRemainsBounded(t *testing.T) {
	c := NewClient("")
	conn := &idleTimeoutTestConn{}
	c.tcpConn = conn
	c.tcpToWebsocket()
	if got := conn.reads.Load(); got != 15 {
		t.Fatalf("handshake reads = %d, want 15", got)
	}
	select {
	case err := <-c.WaitForCompletion():
		if err == nil || !strings.Contains(err.Error(), "target server unresponsive during TLS handshake") {
			t.Fatalf("completion = %v", err)
		}
	default:
		t.Fatal("handshake stall did not terminate")
	}
}

func TestTCPReadPreservesDataWithTerminalError(t *testing.T) {
	c := NewClient("")
	c.cipherSuite = 0x1301
	c.handshakeComplete.Store(true)
	c.httpRequestSent.Store(true)
	records := makeRecords(0x42, 2, 256)
	c.tcpConn = &responseScriptConn{steps: []responseRead{{data: bytes.Join(records, nil), err: io.ErrUnexpectedEOF}}}
	c.tcpToWebsocket()
	if len(c.capturedTraffic) != len(records) {
		t.Fatalf("captured %d records, want %d", len(c.capturedTraffic), len(records))
	}
	for i, record := range records {
		if !bytes.Equal(c.capturedTraffic[i], record) {
			t.Fatalf("record %d corrupted", i)
		}
	}
}
