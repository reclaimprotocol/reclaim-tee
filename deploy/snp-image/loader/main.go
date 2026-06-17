// loader is the init of the STABLE base UKI. It never changes per app release,
// so the base UKI's measurement (PCR 11) is constant and hardcodable. Its job:
// read the app binary from a separate (unmeasured-by-UKI) partition, measure it
// into a dedicated PCR (the cross-cloud-stable "image digest"), then exec it.
// Trust: the loader itself is measured into PCR 11, so a verifier trusting the
// known base knows the app PCR was extended honestly.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// appPCR is a non-resettable PCR left pristine (0) by our GRUB-less, IMA-off
// UKI boot (PCR 9 is NOT usable: the Linux EFI stub measures the initrd into
// it). After Extend, PCR 8 holds ONLY the app identity: sha256(0x00*32 ||
// sha256(app)) — clean, predictable, cross-cloud-stable.
const appPCR = 8

func main() {
	mountPseudo()
	out := console()
	fmt.Fprintln(out, "===== SNP-LOADER =====")
	if err := run(out); err != nil {
		fmt.Fprintln(out, "[loader] FATAL:", err)
		powerOff()
	}
}

func run(out io.Writer) error {
	bin, dev, err := readAppPartition()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	fmt.Fprintf(out, "[loader] app_partition  = %s\n", dev)
	fmt.Fprintf(out, "[loader] app_sha256     = %s\n", hex.EncodeToString(sum[:]))

	// Show the target PCR is pristine before we extend, so the post value is
	// provably sha256(0x00*32 || sha256(app)) and nothing else.
	for _, p := range []uint32{8, 9} {
		if v, err := readPCR(p); err == nil {
			fmt.Fprintf(out, "[loader] PCR%d pre-extend = %s\n", p, hex.EncodeToString(v))
		}
	}

	if err := extendPCR(appPCR, sum[:]); err != nil {
		return fmt.Errorf("extend PCR %d: %w", appPCR, err)
	}
	fmt.Fprintf(out, "[loader] extended PCR %d with app_sha256\n", appPCR)

	if err := syscall.Mount("tmpfs", "/run", "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("mount /run: %w", err)
	}
	const path = "/run/app"
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		return fmt.Errorf("write app: %w", err)
	}
	fmt.Fprintf(out, "[loader] exec %s\n", path)
	return syscall.Exec(path, []string{path}, os.Environ())
}

// readAppPartition reads the length-prefixed app binary from the second
// partition of the boot disk (raw, no filesystem so no fs driver is needed).
// Layout: 8-byte little-endian length, then that many bytes.
func readAppPartition() ([]byte, string, error) {
	for _, dev := range []string{"/dev/nvme0n1p2", "/dev/sda2", "/dev/vda2"} {
		f, err := os.Open(dev)
		if err != nil {
			continue
		}
		var hdr [8]byte
		if _, err := io.ReadFull(f, hdr[:]); err != nil {
			f.Close()
			continue
		}
		n := binary.LittleEndian.Uint64(hdr[:])
		if n == 0 || n > 1<<30 {
			f.Close()
			continue
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(f, buf); err != nil {
			f.Close()
			continue
		}
		f.Close()
		return buf, dev, nil
	}
	return nil, "", fmt.Errorf("no app partition with a valid length header found")
}

func readPCR(idx uint32) ([]byte, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	sel := make([]byte, 3)
	sel[idx/8] |= 1 << (idx % 8)
	resp, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: sel}},
	}}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	if len(resp.PCRValues.Digests) == 0 {
		return nil, fmt.Errorf("no digest")
	}
	return resp.PCRValues.Digests[0].Buffer, nil
}

func extendPCR(idx uint32, digest []byte) error {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return fmt.Errorf("open tpm: %w", err)
	}
	defer tpm.Close()
	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(idx), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{
			{HashAlg: tpm2.TPMAlgSHA256, Digest: digest},
		}},
	}.Execute(tpm)
	return err
}

func mountPseudo() {
	for _, m := range []struct{ src, tgt, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
	} {
		_ = os.MkdirAll(m.tgt, 0o555)
		_ = syscall.Mount(m.src, m.tgt, m.fs, 0, "")
	}
}

func console() io.Writer {
	f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return os.Stdout
	}
	return io.MultiWriter(os.Stdout, f)
}

func powerOff() {
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}
