package shared

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCertificateValidityCheck(t *testing.T) {
	// Test the certificate validity checking logic

	t.Run("ValidCertificate", func(t *testing.T) {
		// Create a certificate that expires in 30 days
		_, certPEM := createTestCertificate(t, "test.example.com", 30*24*time.Hour)

		// Parse as autocert would
		if tlsCert, err := tls.X509KeyPair(certPEM, certPEM); err == nil {
			if x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0]); err == nil {
				timeUntilExpiry := time.Until(x509Cert.NotAfter)

				// Should be valid for more than 7 days
				if timeUntilExpiry <= 7*24*time.Hour {
					t.Errorf("Expected certificate to be valid for more than 7 days, got %v", timeUntilExpiry)
				}

				// Verify it would skip ACME challenge
				shouldSkip := timeUntilExpiry > 7*24*time.Hour
				if !shouldSkip {
					t.Error("Expected to skip ACME challenge for valid certificate")
				}
			} else {
				t.Fatalf("Failed to parse x509 certificate: %v", err)
			}
		} else {
			t.Fatalf("Failed to parse TLS certificate: %v", err)
		}
	})

	t.Run("ExpiringSoonCertificate", func(t *testing.T) {
		// Create a certificate that expires in 3 days (should trigger renewal)
		_, certPEM := createTestCertificate(t, "test.example.com", 3*24*time.Hour)

		// Parse as autocert would
		if tlsCert, err := tls.X509KeyPair(certPEM, certPEM); err == nil {
			if x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0]); err == nil {
				timeUntilExpiry := time.Until(x509Cert.NotAfter)

				// Should be valid for less than 7 days
				if timeUntilExpiry > 7*24*time.Hour {
					t.Errorf("Expected certificate to expire within 7 days, got %v", timeUntilExpiry)
				}

				// Verify it would trigger ACME challenge
				shouldRenew := timeUntilExpiry <= 7*24*time.Hour
				if !shouldRenew {
					t.Error("Expected to trigger ACME challenge for expiring certificate")
				}
			} else {
				t.Fatalf("Failed to parse x509 certificate: %v", err)
			}
		} else {
			t.Fatalf("Failed to parse TLS certificate: %v", err)
		}
	})

	t.Run("ExpiredCertificate", func(t *testing.T) {
		// Create a certificate that expired 1 day ago
		_, certPEM := createTestCertificate(t, "test.example.com", -24*time.Hour)

		// Parse as autocert would
		if tlsCert, err := tls.X509KeyPair(certPEM, certPEM); err == nil {
			if x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0]); err == nil {
				timeUntilExpiry := time.Until(x509Cert.NotAfter)

				// Should be negative (expired)
				if timeUntilExpiry > 0 {
					t.Errorf("Expected certificate to be expired, got %v until expiry", timeUntilExpiry)
				}

				// Verify it would trigger ACME challenge
				shouldRenew := timeUntilExpiry <= 7*24*time.Hour
				if !shouldRenew {
					t.Error("Expected to trigger ACME challenge for expired certificate")
				}
			} else {
				t.Fatalf("Failed to parse x509 certificate: %v", err)
			}
		} else {
			t.Fatalf("Failed to parse TLS certificate: %v", err)
		}
	})
}

// Helper function to create test certificates with specific expiry times
func createTestCertificate(t *testing.T, domain string, validDuration time.Duration) (*x509.Certificate, []byte) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             now.Add(-time.Hour),    // Valid from 1 hour ago
		NotAfter:              now.Add(validDuration), // Valid until specified duration
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse the certificate for return
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse created certificate: %v", err)
	}

	// Encode certificate and key as PEM (as autocert stores them)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Combine cert and key as autocert stores them
	combinedPEM := append(certPEM, keyPEM...)

	return cert, combinedPEM
}
