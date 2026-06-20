#!/bin/bash
set -euo pipefail

# Installs the toolchain to build a dm-verity + UKI bootable image locally with
# mkosi, then prints versions. Run with root: sudo ./deploy/snp-image-setup.sh
# Target host: Ubuntu 24.04 (this WSL2 box).

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi

# The system-wide WSL2 proxy causes flaky TLS to package mirrors; bypass it.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

export DEBIAN_FRONTEND=noninteractive
apt-get update

# mkosi          - image builder (rootfs -> verity -> UKI -> ESP -> GPT)
# systemd-ukify  - assembles the Unified Kernel Image (kernel+initrd+cmdline)
# systemd-boot-efi - sd-boot + sd-stub EFI binaries (sd-stub measures UKI -> PCR 11)
# cryptsetup-bin - veritysetup, builds the dm-verity Merkle tree + root hash
# *-utils/tools  - filesystem + ESP assembly mkosi shells out to
# qemu-system-x86 + ovmf - optional local boot smoke test
# debootstrap    - bootstrap path for debian/ubuntu rootfs
apt-get install -y \
    mkosi \
    systemd-ukify \
    systemd-boot \
    systemd-boot-efi \
    cryptsetup-bin \
    squashfs-tools \
    erofs-utils \
    dosfstools \
    mtools \
    e2fsprogs \
    debootstrap \
    qemu-system-x86 \
    ovmf \
    python3 \
    gdisk

echo
echo "================== VERSIONS =================="
printf "mkosi            "; mkosi --version 2>&1 | head -1 || echo "MISSING"
printf "ukify            "; (ukify --version 2>&1 || /usr/lib/systemd/ukify --version 2>&1 || echo "MISSING") | head -1
printf "veritysetup      "; veritysetup --version 2>&1 | head -1 || echo "MISSING"
printf "systemd-repart   "; systemd-repart --version 2>&1 | head -1 || echo "MISSING"
printf "systemd          "; systemctl --version 2>&1 | head -1 || echo "MISSING"
printf "sd-stub present  "; ls /usr/lib/systemd/boot/efi/linux*.efi.stub 2>/dev/null || echo "MISSING (systemd-boot-efi)"
echo "=============================================="
