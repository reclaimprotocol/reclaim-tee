package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
)

func TestIncrementalTCPStopsAtAuthenticatedRecordBoundary(t *testing.T) {
	for _, suite := range []uint16{minitls.TLS_CHACHA20_POLY1305_SHA256, minitls.TLS_AES_128_GCM_SHA256} {
		for _, tc := range []struct {
			name        string
			content     []string
			badRecord   int
			wantCount   uint64
			wantClose   bool
			wantError   string
			partialTail bool
		}{
			{name: "content length", content: []string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe", "llo"}, badRecord: 3, wantCount: 2},
			{name: "chunked", content: []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", "0\r\n\r\n"}, badRecord: 3, wantCount: 2},
			{name: "close delimited", content: []string{"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello"}, badRecord: 2, wantCount: 2, wantClose: true},
			{name: "partial next header", content: []string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe", "llo"}, badRecord: -1, wantCount: 2, partialTail: true},
			{name: "bad tag before completion", content: []string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe", "llo"}, badRecord: 1, wantError: "authentication tag"},
			{name: "truncated before close", content: []string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe"}, badRecord: 2, wantError: "TLS close_notify before complete HTTP response"},
			{name: "extra HTTP bytes within record", content: []string{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra"}, badRecord: 2, wantError: "HTTP response framing"},
		} {
			t.Run(fmt.Sprintf("%04x/%s", suite, tc.name), func(t *testing.T) {
				c := newIncrementalTestClient(t)
				c.cipherSuite = suite
				var aead cipher.AEAD
				var err error
				if suite == minitls.TLS_CHACHA20_POLY1305_SHA256 {
					aead, err = chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
				} else {
					block, blockErr := aes.NewCipher(make([]byte, 16))
					if blockErr != nil {
						t.Fatal(blockErr)
					}
					aead, err = cipher.NewGCM(block)
				}
				if err != nil {
					t.Fatal(err)
				}
				nonce := func(seq uint64) []byte {
					value := make([]byte, aead.NonceSize())
					binary.BigEndian.PutUint64(value[len(value)-8:], seq)
					return value
				}
				var wire []byte
				addRecord := func(seq uint64, content []byte, contentType byte) {
					plaintext := append(bytes.Clone(content), contentType)
					length := len(plaintext) + aead.Overhead()
					header := []byte{23, 3, 3, byte(length >> 8), byte(length)}
					sealed := aead.Seal(nil, nonce(seq), plaintext, header)
					if int(seq) == tc.badRecord {
						sealed[len(sealed)-1] ^= 1
					}
					wire = append(wire, header...)
					wire = append(wire, sealed...)
				}
				for seq, content := range tc.content {
					addRecord(uint64(seq), []byte(content), minitls.RecordTypeApplicationData)
				}
				if tc.partialTail {
					wire = append(wire, 23, 3, 3)
				} else {
					addRecord(uint64(len(tc.content)), []byte{1, 0}, minitls.RecordTypeAlert)
					addRecord(uint64(len(tc.content)+1), []byte{1, 0}, minitls.RecordTypeAlert)
				}

				finalized := make(chan *teeproto.FinalizeResponse, 1)
				c.wsConn = incrementalTestWebSocket(t, func(env *teeproto.Envelope) {
					if ready := env.GetResponseCaptureReady(); ready != nil {
						if err := c.receiveResponseCaptureReady(c.sessionID, &teeproto.ResponseCaptureReady{SessionBinding: ready.SessionBinding, Acknowledged: true}); err != nil {
							t.Error(err)
						}
					}
					if f := env.GetFinalizeResponse(); f != nil {
						finalized <- f
					}
				})
				var submitted atomic.Uint64
				c.teetConn = incrementalTestWebSocket(t, func(env *teeproto.Envelope) {
					batch := env.GetBatchedEncryptedResponses()
					if batch == nil {
						t.Error("unexpected message to authentication peer")
						return
					}
					streams := &teeproto.BatchedDecryptionStreams{SessionId: c.sessionID, Metadata: proto.Clone(batch.Metadata).(*teeproto.ResponseBatchMetadata), TotalCount: batch.TotalCount}
					for _, record := range batch.Responses {
						seq := submitted.Add(1) - 1
						if record.SeqNum != seq {
							t.Errorf("submitted sequence %d, want %d", record.SeqNum, seq)
						}
						sealed := append(bytes.Clone(record.EncryptedData), record.Tag...)
						plaintext, err := aead.Open(nil, nonce(seq), sealed, record.RecordHeader)
						if err != nil {
							c.terminateConnectionWithError("test peer rejected authentication tag", err)
							return
						}
						stream := make([]byte, len(plaintext))
						for i := range stream {
							stream[i] = plaintext[i] ^ record.EncryptedData[i]
						}
						streams.DecryptionStreams = append(streams.DecryptionStreams, &teeproto.ResponseDecryptionStreamData{SeqNum: seq, Length: int32(len(stream)), DecryptionStream: stream})
					}
					// Release streams only after every record in the submitted batch
					// passes real AEAD authentication, as the TEEs require.
					if err := c.receiveIncrementalDecryption(c.sessionID, streams); err != nil {
						t.Error(err)
						c.terminateConnectionWithError("test peer decryption reply", err)
					}
				})
				t.Cleanup(c.Close)
				conn := &responseScriptConn{steps: []responseRead{{data: wire}}}
				c.tcpConn = conn
				done := make(chan struct{})
				go func() { c.tcpToWebsocket(); close(done) }()
				select {
				case freeze := <-finalized:
					if tc.wantError != "" {
						t.Fatal("invalid response requested a freeze")
					}
					if freeze.RecordCount != tc.wantCount || freeze.BatchCount != tc.wantCount || submitted.Load() != tc.wantCount {
						t.Fatalf("wrong authenticated boundary: freeze=%v submitted=%d", freeze, submitted.Load())
					}
					if c.responseReconstructed {
						t.Fatal("response reconstructed before freeze acknowledgment")
					}
					if err := c.receiveResponseFrozen(c.sessionID, &teeproto.ResponseFrozen{SessionBinding: freeze.SessionBinding, BatchCount: freeze.BatchCount, RecordCount: freeze.RecordCount, PrefixCommitment: freeze.PrefixCommitment}); err != nil {
						t.Fatal(err)
					}
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("capture did not finish after freeze acknowledgment")
					}
					if !c.responseReconstructed || c.incrementalResponse.closeNotify != tc.wantClose || conn.next != 1 || uint64(len(c.capturedTraffic)) != tc.wantCount {
						t.Fatal("capture crossed the authenticated completion boundary")
					}
				case <-done:
					if tc.wantError == "" {
						t.Fatalf("capture failed before freeze after submitting %d records, including the invalid trailing record", submitted.Load())
					}
					if c.responseReconstructed {
						t.Fatal("invalid response was reconstructed")
					}
					select {
					case err := <-c.WaitForCompletion():
						if err == nil || !strings.Contains(err.Error(), tc.wantError) {
							t.Fatalf("unexpected protocol result: %v", err)
						}
					case <-time.After(time.Second):
						t.Fatal("invalid response did not publish a protocol error")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("capture did not reach an authenticated boundary or error")
				}
			})
		}
	}
}
