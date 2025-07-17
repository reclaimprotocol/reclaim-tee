package minitls

import (
	"bytes"
	"io"
	"testing"
)

// TestTLS12RecordBasic tests basic TLS 1.2 record read/write functionality
func TestTLS12RecordBasic(t *testing.T) {
	// Test data
	testFragment := []byte("Hello, TLS 1.2!")

	// Create a test record
	originalRecord := &TLS12Record{
		Type:     recordTypeApplicationData,
		Version:  VersionTLS12,
		Length:   uint16(len(testFragment)),
		Fragment: testFragment,
	}

	// Write the record to a buffer
	var buf bytes.Buffer
	writer := NewTLS12RecordWriter(&buf)

	err := writer.WriteRecord(originalRecord)
	if err != nil {
		t.Fatalf("Failed to write record: %v", err)
	}

	// Verify the buffer contains the expected data
	expectedLen := 5 + len(testFragment) // 5-byte header + fragment
	if buf.Len() != expectedLen {
		t.Errorf("Buffer length = %d, want %d", buf.Len(), expectedLen)
	}

	// Read the record back
	reader := NewTLS12RecordReader(&buf)
	readRecord, err := reader.ReadRecord()
	if err != nil {
		t.Fatalf("Failed to read record: %v", err)
	}

	// Verify the record matches
	if readRecord.Type != originalRecord.Type {
		t.Errorf("Record type = %d, want %d", readRecord.Type, originalRecord.Type)
	}
	if readRecord.Version != originalRecord.Version {
		t.Errorf("Record version = 0x%04x, want 0x%04x", readRecord.Version, originalRecord.Version)
	}
	if readRecord.Length != originalRecord.Length {
		t.Errorf("Record length = %d, want %d", readRecord.Length, originalRecord.Length)
	}
	if !bytes.Equal(readRecord.Fragment, originalRecord.Fragment) {
		t.Errorf("Record fragment = %q, want %q", readRecord.Fragment, originalRecord.Fragment)
	}

	t.Logf("TLS 1.2 record round-trip successful: %d bytes", len(testFragment))
}

// TestTLS12RecordValidation tests record validation
func TestTLS12RecordValidation(t *testing.T) {
	testCases := []struct {
		name        string
		record      *TLS12Record
		expectError bool
	}{
		{
			name: "Valid handshake record",
			record: &TLS12Record{
				Type:     recordTypeHandshake,
				Version:  VersionTLS12,
				Length:   4,
				Fragment: []byte{1, 0, 0, 0}, // ClientHello stub
			},
			expectError: false,
		},
		{
			name: "Invalid record type",
			record: &TLS12Record{
				Type:     19, // Invalid
				Version:  VersionTLS12,
				Length:   1,
				Fragment: []byte{0},
			},
			expectError: true,
		},
		{
			name: "Invalid version",
			record: &TLS12Record{
				Type:     recordTypeApplicationData,
				Version:  0x0301, // TLS 1.0
				Length:   1,
				Fragment: []byte{0},
			},
			expectError: true,
		},
		{
			name: "Length mismatch",
			record: &TLS12Record{
				Type:     recordTypeApplicationData,
				Version:  VersionTLS12,
				Length:   5,         // Says 5 bytes
				Fragment: []byte{0}, // But only 1 byte
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := NewTLS12RecordWriter(&buf)

			err := writer.WriteRecord(tc.record)
			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestTLS12RecordMultiple tests reading multiple records
func TestTLS12RecordMultiple(t *testing.T) {
	// Create multiple test records
	records := []*TLS12Record{
		{
			Type:     recordTypeHandshake,
			Version:  VersionTLS12,
			Length:   5,
			Fragment: []byte{1, 0, 0, 1, 42}, // ClientHello stub
		},
		{
			Type:     recordTypeApplicationData,
			Version:  VersionTLS12,
			Length:   3,
			Fragment: []byte{'H', 'i', '!'},
		},
		{
			Type:     recordTypeAlert,
			Version:  VersionTLS12,
			Length:   2,
			Fragment: []byte{1, 0}, // Warning, close_notify
		},
	}

	// Write all records to buffer
	var buf bytes.Buffer
	writer := NewTLS12RecordWriter(&buf)

	for i, record := range records {
		if err := writer.WriteRecord(record); err != nil {
			t.Fatalf("Failed to write record %d: %v", i, err)
		}
	}

	// Read all records back
	reader := NewTLS12RecordReader(&buf)

	for i, expectedRecord := range records {
		readRecord, err := reader.ReadRecord()
		if err != nil {
			t.Fatalf("Failed to read record %d: %v", i, err)
		}

		if readRecord.Type != expectedRecord.Type {
			t.Errorf("Record %d type = %d, want %d", i, readRecord.Type, expectedRecord.Type)
		}
		if !bytes.Equal(readRecord.Fragment, expectedRecord.Fragment) {
			t.Errorf("Record %d fragment = %v, want %v", i, readRecord.Fragment, expectedRecord.Fragment)
		}
	}

	t.Logf("Successfully read/wrote %d TLS 1.2 records", len(records))
}

// slowReader simulates a slow network connection by returning 1 byte at a time
type slowReader struct {
	data []byte
	pos  int
}

func (sr *slowReader) Read(p []byte) (n int, err error) {
	if sr.pos >= len(sr.data) {
		return 0, io.EOF
	}

	// Return at most 1 byte
	n = 1
	if len(p) == 0 {
		return 0, nil
	}

	p[0] = sr.data[sr.pos]
	sr.pos++
	return n, nil
}
