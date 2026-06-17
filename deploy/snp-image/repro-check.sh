#!/bin/bash
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true

# Builds the image twice and diffs the extracted root filesystems to pinpoint
# which files are non-deterministic (the reason the verity roothash drifts
# across rebuilds). Runs in the privileged mkosi container.

cd /work

build_and_manifest() {
    local n=$1
    echo "[repro] build ${n}..." >&2
    mkosi --force >/dev/null 2>&1 || { echo "mkosi failed" >&2; exit 1; }
    local loop root
    loop="$(losetup --show -fP /work/snp-verity.raw)"
    root=""
    for p in "${loop}"p*; do
        if fsck.erofs "${p}" >/dev/null 2>&1; then root="${p}"; break; fi
    done
    [[ -n "${root}" ]] || { echo "no erofs partition found" >&2; losetup -d "${loop}"; exit 1; }
    rm -rf "/tmp/r${n}"; mkdir -p "/tmp/r${n}"
    fsck.erofs --extract="/tmp/r${n}" "${root}" >/dev/null 2>&1
    losetup -d "${loop}"
    ( cd "/tmp/r${n}" && { find . -type f -exec sha256sum {} \; ; find . -type l -printf '%p SYMLINK %l\n'; } | sort -k1 > "/work/manifest.${n}.txt" )
    echo "[repro] manifest ${n}: $(wc -l < /work/manifest.${n}.txt) entries" >&2
}

build_and_manifest a
build_and_manifest b

echo "===== files whose CONTENT differs between two identical builds ====="
# Compare by path: list paths whose hash changed or that exist in only one.
join -j2 -a1 -a2 -e MISSING -o '0,1.1,2.1' \
    <(awk '{print $2" "$1}' /work/manifest.a.txt | sort) \
    <(awk '{print $2" "$1}' /work/manifest.b.txt | sort) \
    | awk '$2 != $3 {print $1}' | sort -u
echo "===== count ====="
join -j2 -a1 -a2 -e MISSING -o '0,1.1,2.1' \
    <(awk '{print $2" "$1}' /work/manifest.a.txt | sort) \
    <(awk '{print $2" "$1}' /work/manifest.b.txt | sort) \
    | awk '$2 != $3' | wc -l
