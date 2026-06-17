// snp-poc proves we can pull and verify a raw SEV-SNP attestation report on a
// plain GCP Confidential VM (N2D), i.e. outside the Confidential Space launcher.
// It mirrors the report_data layout sketched in MULTI_PAIR_ARCHITECTURE_PLAN.md
// Appendix C: [0..32)=sha256(SPKI placeholder), [32..64)=sha256(self binary).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-sev-guest/client"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
)

func main() {
	skipVerify := flag.Bool("skip-verify", false, "skip AMD signature-chain verification (no KDS egress)")
	flag.Parse()

	if err := run(*skipVerify); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(skipVerify bool) error {
	reportData, binHash, err := buildReportData()
	if err != nil {
		return err
	}
	fmt.Printf("report_data (64B) = %s\n", hex.EncodeToString(reportData[:]))
	fmt.Printf("  [ 0..32) spki_placeholder = %s\n", hex.EncodeToString(reportData[:32]))
	fmt.Printf("  [32..64) sha256(self bin) = %s\n", hex.EncodeToString(binHash[:]))

	d, err := client.OpenDevice()
	if err != nil {
		return fmt.Errorf("open /dev/sev-guest (is this a SEV-SNP CVM?): %w", err)
	}
	defer d.Close()

	att, err := client.GetExtendedReport(d, reportData)
	if err != nil {
		return fmt.Errorf("get extended report: %w", err)
	}
	report := att.GetReport()

	fmt.Println("--- report ---")
	fmt.Printf("version            = %d\n", report.GetVersion())
	fmt.Printf("vmpl               = %d\n", report.GetVmpl())
	fmt.Printf("policy             = 0x%x\n", report.GetPolicy())
	fmt.Printf("measurement (48B)  = %s\n", hex.EncodeToString(report.GetMeasurement()))
	fmt.Printf("report_data echoed = %s\n", hex.EncodeToString(report.GetReportData()))
	fmt.Printf("host_data (32B)    = %s\n", hex.EncodeToString(report.GetHostData()))
	fmt.Printf("chip_id (64B)      = %s\n", hex.EncodeToString(report.GetChipId()))

	certs := att.GetCertificateChain()
	fmt.Printf("cert_chain present = vcek:%d ask:%d ark:%d\n",
		len(certs.GetVcekCert()), len(certs.GetAskCert()), len(certs.GetArkCert()))

	if !bytesEqual(report.GetReportData(), reportData[:]) {
		return fmt.Errorf("report_data round-trip mismatch")
	}
	fmt.Println("report_data round-trip OK")

	if skipVerify {
		fmt.Println("verification SKIPPED (--skip-verify)")
		return dumpJSON(report)
	}

	opts := verify.DefaultOptions()
	if err := verify.SnpAttestation(att, opts); err != nil {
		return fmt.Errorf("AMD chain verification failed: %w", err)
	}
	fmt.Println("AMD signature-chain verification OK")
	return dumpJSON(report)
}

// buildReportData lays out the 64-byte user field: a fixed placeholder where
// the real SPKI hash will go, and sha256 of this running binary.
func buildReportData() ([64]byte, [32]byte, error) {
	var rd [64]byte
	spkiPlaceholder := sha256.Sum256([]byte("reclaim-snp-poc-spki-placeholder"))
	copy(rd[:32], spkiPlaceholder[:])

	binHash, err := selfHash()
	if err != nil {
		return rd, binHash, err
	}
	copy(rd[32:], binHash[:])
	return rd, binHash, nil
}

func selfHash() ([32]byte, error) {
	var sum [32]byte
	exe, err := os.Executable()
	if err != nil {
		return sum, fmt.Errorf("locate self: %w", err)
	}
	f, err := os.Open(exe)
	if err != nil {
		return sum, fmt.Errorf("open self: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("hash self: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dumpJSON(report *pb.Report) error {
	out := map[string]string{
		"measurement": hex.EncodeToString(report.GetMeasurement()),
		"report_data": hex.EncodeToString(report.GetReportData()),
		"chip_id":     hex.EncodeToString(report.GetChipId()),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println("--- summary json ---")
	fmt.Println(string(b))
	return nil
}
