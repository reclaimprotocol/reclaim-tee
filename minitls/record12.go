package minitls

import (
	"encoding/binary"
	"fmt"
	"io"
)

// TLS 1.2 Record Layer Implementation
// Based on RFC 5246 and Go's crypto/tls patterns

// TLS12Record represents a TLS 1.2 record with explicit sequence numbers
type TLS12Record struct {
	Type     uint8  // Content type (20=change_cipher_spec, 21=alert, 22=handshake, 23=application_data)
	Version  uint16 // Protocol version (0x0303 for TLS 1.2)
	Length   uint16 // Length of the fragment
	Fragment []byte // The record fragment (plaintext or ciphertext)
}

// TLS12RecordReader handles reading TLS 1.2 records from a connection
type TLS12RecordReader struct {
	conn   io.Reader
	buffer []byte // Buffer for incomplete records
}

// TLS12RecordWriter handles writing TLS 1.2 records to a connection
type TLS12RecordWriter struct {
	conn io.Writer
}

// NewTLS12RecordReader creates a new TLS 1.2 record reader
func NewTLS12RecordReader(conn io.Reader) *TLS12RecordReader {
	return &TLS12RecordReader{
		conn:   conn,
		buffer: make([]byte, 0, 8192), // 8KB initial buffer
	}
}

// NewTLS12RecordWriter creates a new TLS 1.2 record writer
func NewTLS12RecordWriter(conn io.Writer) *TLS12RecordWriter {
	return &TLS12RecordWriter{
		conn: conn,
	}
}

// ReadRecord reads a complete TLS 1.2 record from the connection
func (r *TLS12RecordReader) ReadRecord() (*TLS12Record, error) {
	// Ensure we have at least 5 bytes for the record header
	for len(r.buffer) < 5 {
		if err := r.fillBuffer(5 - len(r.buffer)); err != nil {
			return nil, fmt.Errorf("failed to read record header: %v", err)
		}
	}

	// Parse the record header
	record := &TLS12Record{
		Type:    r.buffer[0],
		Version: binary.BigEndian.Uint16(r.buffer[1:3]),
		Length:  binary.BigEndian.Uint16(r.buffer[3:5]),
	}

	// Validate record type
	if record.Type < 20 || record.Type > 23 {
		return nil, fmt.Errorf("invalid TLS record type: %d", record.Type)
	}

	// Validate TLS version (accept both TLS 1.2 and TLS 1.3 for compatibility)
	if record.Version != VersionTLS12 && record.Version != VersionTLS13 {
		return nil, fmt.Errorf("unsupported TLS version: 0x%04x", record.Version)
	}

	// Check for reasonable record length (max 16KB + overhead per RFC 5246)
	if record.Length > 16384+2048 {
		return nil, fmt.Errorf("record too large: %d bytes", record.Length)
	}

	// Ensure we have the complete record fragment
	totalRecordSize := 5 + int(record.Length)
	for len(r.buffer) < totalRecordSize {
		needed := totalRecordSize - len(r.buffer)
		if err := r.fillBuffer(needed); err != nil {
			return nil, fmt.Errorf("failed to read record fragment: %v", err)
		}
	}

	// Extract the fragment
	record.Fragment = make([]byte, record.Length)
	copy(record.Fragment, r.buffer[5:5+record.Length])

	// Remove the consumed record from the buffer
	r.buffer = r.buffer[totalRecordSize:]

	return record, nil
}

// fillBuffer reads at least minBytes from the connection into the buffer
func (r *TLS12RecordReader) fillBuffer(minBytes int) error {
	readBuf := make([]byte, max(minBytes, 4096)) // Read at least 4KB for efficiency
	n, err := r.conn.Read(readBuf)
	if err != nil {
		return err
	}
	r.buffer = append(r.buffer, readBuf[:n]...)
	return nil
}

// WriteRecord writes a TLS 1.2 record to the connection
func (w *TLS12RecordWriter) WriteRecord(record *TLS12Record) error {
	// Validate record
	if record.Type < 20 || record.Type > 23 {
		return fmt.Errorf("invalid TLS record type: %d", record.Type)
	}
	if record.Version != VersionTLS12 {
		return fmt.Errorf("invalid TLS version for TLS 1.2 record: 0x%04x", record.Version)
	}
	if len(record.Fragment) != int(record.Length) {
		return fmt.Errorf("fragment length mismatch: declared %d, actual %d", record.Length, len(record.Fragment))
	}

	// Construct the record
	recordBytes := make([]byte, 5+len(record.Fragment))
	recordBytes[0] = record.Type
	binary.BigEndian.PutUint16(recordBytes[1:3], record.Version)
	binary.BigEndian.PutUint16(recordBytes[3:5], record.Length)
	copy(recordBytes[5:], record.Fragment)

	// Write to connection
	_, err := w.conn.Write(recordBytes)
	return err
}
