#!/bin/bash
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true

# Two-tier image (in container): a STABLE base UKI (kernel + loader init) whose
# measurement (PCR 11) never changes per app release, plus the app binary on a
# SEPARATE raw partition. The loader measures the app into PCR 9 and execs it.
# So PCR 11 = stable base (hardcode), PCR 9 = sha256-derived app id (changeable,
# cross-cloud-stable) — the Confidential-Space image_digest equivalent.

export SOURCE_DATE_EPOCH=1735689600
cd /work

LOADER=/work/mkosi.extra/usr/local/bin/snp-loader
# APP defaults to the prober; the `tee` build sets APP_BIN to the real tee_t.
APP="${APP_BIN:-/work/mkosi.extra/usr/local/bin/snp-prober}"
[[ -f "${LOADER}" && -f "${APP}" ]] || { echo "loader/app binary missing: ${LOADER} / ${APP}" >&2; exit 1; }
KERNEL="$(ls /boot/vmlinuz-*-gcp 2>/dev/null | sort | tail -1)"
STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
CMDLINE="console=ttyS0,115200"
SEED=b5f8a3c2-1d4e-4a6b-9c8d-7e0f1a2b3c4d

# 1) STABLE base initrd: loader as /init (no app code -> base never changes per release).
rm -rf /tmp/ir; mkdir -p /tmp/ir/proc /tmp/ir/sys /tmp/ir/dev /tmp/ir/run
cp "${LOADER}" /tmp/ir/init; chmod 0755 /tmp/ir/init

# Bundle the cloud NIC driver (gve on GCP — not builtin; the loader inserts it).
# Decompressed here so the loader can use a plain finit_module.
mkdir -p /tmp/ir/modules
KVER="$(ls /usr/lib/modules | head -1)"
GVE="$(find "/usr/lib/modules/${KVER}" -name 'gve.ko*' | head -1)"
if [[ -n "${GVE}" ]]; then
    case "${GVE}" in
        *.zst) zstd -dqf -o /tmp/ir/modules/gve.ko "${GVE}" ;;
        *)     cp "${GVE}" /tmp/ir/modules/gve.ko ;;
    esac
    echo "[tier] bundled NIC module: gve.ko ($(du -h /tmp/ir/modules/gve.ko | cut -f1))"
fi

# cpio --reproducible normalizes inode/device numbers but NOT mtimes, and the
# freshly-built loader has a per-build mtime; clamp everything to the epoch.
find /tmp/ir -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
( cd /tmp/ir && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort \
    | cpio --reproducible --quiet -o -H newc -R 0:0 ) | zstd -q -19 -f -o /work/base-initrd.zst

# 2) STABLE base UKI -> PCR 11.
ukify build --linux="${KERNEL}" --initrd=/work/base-initrd.zst \
    --cmdline="${CMDLINE}" --stub "${STUB}" --output /work/snp-base.efi

# Assemble the systemd-repart source root. Note: with --root=, repart resolves
# CopyFiles= AND CopyBlocks= RELATIVE to this root, so the app blob lives here.
rm -rf /tmp/sysroot; mkdir -p /tmp/sysroot/EFI/BOOT
cp /work/snp-base.efi /tmp/sysroot/EFI/BOOT/BOOTX64.EFI

# 3) App blob: 8-byte LE length + app binary, padded to the partition size.
APPSZ=96
python3 -c 'import sys,struct
d=open(sys.argv[1],"rb").read()
b=struct.pack("<Q",len(d))+d
b=b.ljust(int(sys.argv[3])*1024*1024,b"\x00")
open(sys.argv[2],"wb").write(b)' "${APP}" /tmp/sysroot/app.blob "${APPSZ}"
[[ -f /tmp/sysroot/app.blob ]] || { echo "[tier] failed to create app.blob" >&2; exit 1; }
echo "[tier] app.blob: $(stat -c%s /tmp/sysroot/app.blob) bytes"

# 4) Disk: ESP (base UKI at fallback path) + raw app partition (CopyBlocks).
mkdir -p /tmp/defs
cat > /tmp/defs/00-esp.conf <<'EOF'
[Partition]
Type=esp
Format=vfat
CopyFiles=/EFI:/EFI
SizeMinBytes=512M
SizeMaxBytes=512M
EOF
cat > /tmp/defs/10-app.conf <<EOF
[Partition]
Type=linux-generic
CopyBlocks=/app.blob
SizeMinBytes=${APPSZ}M
SizeMaxBytes=${APPSZ}M
EOF
rm -f /work/snp-tier.raw
systemd-repart --empty=create --size=auto --seed="${SEED}" \
    --definitions=/tmp/defs --root=/tmp/sysroot --dry-run=no /work/snp-tier.raw

# 5) Report the values a verifier would pin.
APPSHA="$(sha256sum "${APP}" | cut -d' ' -f1)"
echo "[tier] base UKI: $(du -h /work/snp-base.efi | cut -f1)  raw: $(du -h /work/snp-tier.raw | cut -f1)"
echo "[tier] base_uki_sha256 = $(sha256sum /work/snp-base.efi | cut -d' ' -f1)  (stable across app changes)"
echo "[tier] app_sha256      = ${APPSHA}"
echo "[tier] expected_PCR8   = $(python3 -c "import hashlib,binascii;print(hashlib.sha256(b'\x00'*32+binascii.unhexlify('${APPSHA}')).hexdigest())")  (app, if PCR8 pristine)"
M=/usr/lib/systemd/systemd-measure
[[ -x "${M}" ]] && { echo "[tier] predicted PCR11 (base):"; "${M}" calculate --linux="${KERNEL}" --initrd=/work/base-initrd.zst --cmdline="${CMDLINE}" --stub "${STUB}" 2>/dev/null | grep -iE '11:' | head -2 || true; }
