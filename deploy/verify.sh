#!/bin/bash
set -euo pipefail

# =============================================================================
# RECLAIM TEE IMAGE VERIFICATION
# =============================================================================
# Rebuilds CS images, SNP bases, and app bundles from source and checks their digests
# against deploy/image-history.json. No cloud credentials or signing keys needed.
# SNP bases reuse the recorded release signature and the public R certificate.
#
# Uses the same pinned BuildKit image as build.sh to ensure identical output.
#
# Requirements:
#   - Docker with buildx
#   - Go, Python 3, OpenSSL, and GNU tar
#
# Usage:
#   ./verify.sh                              verify the latest recorded builds
#   ./verify.sh --app <digest>               verify a recorded SNP app
#   ./verify.sh --base <digest>              verify a recorded signed SNP base
# Selectors can be combined or repeated. Only selected builds are verified.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
HISTORY="${SCRIPT_DIR}/image-history.json"

usage() {
    echo "Usage: $0 [--app <digest>] [--base <digest>]"
    echo 'Use bare hexadecimal digests without snp-app: or snp-base: prefixes.'
    echo 'Without selectors, verify the latest recorded builds.'
    echo 'Repeat or combine selectors to verify specific SNP apps and signed bases.'
}
APP_DIGESTS=()
BASE_DIGESTS=()
TARGETED=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --app|--base)
            [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR: $1 requires a digest" >&2; exit 1; }
            if [[ "$1" == --app ]]; then APP_DIGESTS+=("$2"); else BASE_DIGESTS+=("$2"); fi
            TARGETED=true
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# Same pinned BuildKit image as build.sh -- must match exactly
BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"

VERIFY_DIR=$(mktemp -d)
WORKTREE_DIR=""
cleanup() {
    if [[ -n "${WORKTREE_DIR}" && -d "${WORKTREE_DIR}" ]]; then
        git -C "${REPO_ROOT}" worktree remove --force "${WORKTREE_DIR}" 2>/dev/null || true
    fi
    rm -rf "${VERIFY_DIR}"
}
trap cleanup EXIT

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

if [[ ! -f "${HISTORY}" ]]; then
    echo "ERROR: ${HISTORY} not found"
    exit 1
fi

# Validate SNP entries before building. Write the selection to a file so Python
# errors propagate to the script rather than disappearing in process substitution.
# Bash 3.2 treats empty arrays as unset under nounset. Omit empty selector arrays
# from argv while preserving each argument when selectors are present.
python3 - "${HISTORY}" "${TARGETED}" ${APP_DIGESTS[@]+"${APP_DIGESTS[@]}"} >"${VERIFY_DIR}/snp-apps" <<'PY'
import json
import re
import sys

apps = [a for a in json.load(open(sys.argv[1])).get('app_images', [])
        if a.get('type') == 'sev-snp']
selected = []
if sys.argv[2] == 'true':
    for digest in dict.fromkeys(sys.argv[3:]):
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            sys.exit(f'ERROR: invalid SNP app selector: {digest}')
        matches = [a for a in apps if a.get('version') == 'snp-app:' + digest]
        if len(matches) != 1:
            sys.exit(f'ERROR: expected one recorded SNP app for {digest}, found {len(matches)}')
        selected.append(matches[0])
elif apps:
    for role in ('k', 't'):
        entry = next((a for a in reversed(apps) if a.get('role') == role), None)
        if entry is None:
            sys.exit(f'ERROR: missing SNP app entry for tee_{role}')
        selected.append(entry)
for entry in selected:
    role = entry.get('role')
    if role not in ('k', 't'):
        sys.exit('ERROR: SNP app role must be k or t')
    commit = entry.get('sourceCommit', '')
    digest = entry.get('version', '')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        sys.exit(f'ERROR: invalid sourceCommit for SNP tee_{role}')
    if not isinstance(digest, str) or not re.fullmatch(r'snp-app:[0-9a-f]{64}', digest):
        sys.exit(f'ERROR: invalid app digest for SNP tee_{role}')
    print(role, commit, digest)
PY

# Require complete evidence for each selected base (latest per cloud by default). A
# legacy entry without a signature must fail instead of silently skipping bases.
python3 -B - "${HISTORY}" "${SCRIPT_DIR}/snp-image" "${TARGETED}" ${BASE_DIGESTS[@]+"${BASE_DIGESTS[@]}"} >"${VERIFY_DIR}/snp-bases" <<'PY'
import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location('base_history', sys.argv[2] + '/base-history.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
history = json.load(open(sys.argv[1]))
if sys.argv[3] == 'true':
    selected = [module.select(history, digest=digest) for digest in dict.fromkeys(sys.argv[4:])]
else:
    clouds = {entry['cloud'] for entry in history.get('base_images', [])}
    selected = [module.select(history, cloud) for cloud in sorted(clouds)]
for entry in selected:
    module.validate(entry)
    print(entry['cloud'], entry['base'].split(':', 1)[1])
PY

PASS=true
VERIFIED=0

# CS and SNP app checks are independent. An empty CS set skips only CS builds.
CS_COUNT=0
if [[ "${TARGETED}" == false ]]; then
    CS_COUNT=$(python3 -c "import json; d=json.load(open('${HISTORY}')); print(sum(1 for e in d.get('app_images',[]) if e.get('type','cs')=='cs'))")
fi
if [[ "${CS_COUNT}" == "0" ]]; then
    log "No CS images selected for verification, skipping."
else

# Extract the latest CS tee-k / tee-t app entry + build metadata.
read -r EXPECTED_TK SOURCE_COMMIT_TK SOURCE_EPOCH_TK < <(python3 -c "
import json
d = json.load(open('${HISTORY}'))
for e in reversed(d.get('app_images', [])):
    if e.get('type','cs')=='cs' and '/tee-k' in e.get('package',''):
        print(e['version'], e.get('sourceCommit',''), e.get('sourceDateEpoch',''))
        break
")

read -r EXPECTED_TT SOURCE_COMMIT_TT SOURCE_EPOCH_TT < <(python3 -c "
import json
d = json.load(open('${HISTORY}'))
for e in reversed(d.get('app_images', [])):
    if e.get('type','cs')=='cs' and '/tee-t' in e.get('package',''):
        print(e['version'], e.get('sourceCommit',''), e.get('sourceDateEpoch',''))
        break
")

if [[ -z "${EXPECTED_TK}" || -z "${EXPECTED_TT}" ]]; then
    echo "ERROR: Could not extract expected digests from ${HISTORY}"
    exit 1
fi

# Validate both services were built with the same epoch
if [[ -n "${SOURCE_EPOCH_TK}" && -n "${SOURCE_EPOCH_TT}" && "${SOURCE_EPOCH_TK}" != "${SOURCE_EPOCH_TT}" ]]; then
    log "ERROR: TEE-K and TEE-T were built with different SOURCE_DATE_EPOCH values"
    exit 1
fi

# Require both services to reference the same source commit.
if [[ -n "${SOURCE_COMMIT_TK}" && -n "${SOURCE_COMMIT_TT}" && "${SOURCE_COMMIT_TK}" != "${SOURCE_COMMIT_TT}" ]]; then
    log "ERROR: TEE-K and TEE-T have different sourceCommit values"
    exit 1
fi

BUILD_COMMIT="${SOURCE_COMMIT_TK:-${SOURCE_COMMIT_TT}}"
if [[ -z "${BUILD_COMMIT}" ]]; then
    log "ERROR: image-history.json entry has no sourceCommit -- cannot verify reproducibility"
    exit 1
fi

if ! git -C "${REPO_ROOT}" rev-parse --verify "${BUILD_COMMIT}^{commit}" >/dev/null 2>&1; then
    log "ERROR: sourceCommit ${BUILD_COMMIT} not found in repository"
    exit 1
fi

# Determine SOURCE_DATE_EPOCH from history (preferred) or the recorded commit's time.
EPOCH="${SOURCE_EPOCH_TK:-${SOURCE_EPOCH_TT}}"
if [[ -n "${EPOCH}" ]]; then
    export SOURCE_DATE_EPOCH="${EPOCH}"
    log "Using SOURCE_DATE_EPOCH from image-history.json: ${SOURCE_DATE_EPOCH}"
else
    export SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct "${BUILD_COMMIT}")
    log "WARNING: No sourceDateEpoch in history, using commit time: ${SOURCE_DATE_EPOCH}"
fi

log "Verifying recorded build commit: ${BUILD_COMMIT:0:12}"

# Verify against the commit the image was released from, not HEAD. The property
# being checked is "the recorded image is reproducible from its recorded source
# commit" -- which is independent of what's happening on the current branch.
WORKTREE_DIR="${VERIFY_DIR}/src"
git -C "${REPO_ROOT}" worktree add --detach "${WORKTREE_DIR}" "${BUILD_COMMIT}" >/dev/null

# Normalize file mtimes to SOURCE_DATE_EPOCH. rewrite-timestamp only clamps
# timestamps NEWER than the epoch, so older mtimes from different checkouts
# would otherwise produce different layers.
find "${WORKTREE_DIR}" -not -path '*/.git/*' -exec touch -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

# Create/reuse pinned builder (same image as build.sh)
BUILDER_NAME="reclaim-repro"
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    log "Creating pinned builder: ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container \
        --driver-opt image="${BUILDKIT_IMAGE}" \
        --bootstrap
fi
BUILDER_FLAG="--builder=${BUILDER_NAME}"

log "Expected digests from image-history.json:"
log "  TEE-K: ${EXPECTED_TK}"
log "  TEE-T: ${EXPECTED_TT}"

# Build TEE-K
log "Building TEE-K from source..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${WORKTREE_DIR}/tee_k/Dockerfile.enclave" \
    -o type=oci,dest="${VERIFY_DIR}/tee-k.tar",rewrite-timestamp=true \
    "${WORKTREE_DIR}"

# Build TEE-T
log "Building TEE-T from source..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${WORKTREE_DIR}/tee_t/Dockerfile.enclave" \
    -o type=oci,dest="${VERIFY_DIR}/tee-t.tar",rewrite-timestamp=true \
    "${WORKTREE_DIR}"

# Extract digests
extract_digest() {
    local tarball="$1"
    local dir="${tarball%.tar}-oci"
    mkdir -p "${dir}"
    tar -xf "${tarball}" -C "${dir}"
    python3 -c "import json; print(json.load(open('${dir}/index.json'))['manifests'][0]['digest'])"
}

ACTUAL_TK=$(extract_digest "${VERIFY_DIR}/tee-k.tar")
ACTUAL_TT=$(extract_digest "${VERIFY_DIR}/tee-t.tar")

# Compare
echo ""
echo "============================================="
echo "Verification Results:"
echo "============================================="

echo "TEE-K:"
echo "  Expected: ${EXPECTED_TK}"
echo "  Actual:   ${ACTUAL_TK}"
if [[ "${EXPECTED_TK}" == "${ACTUAL_TK}" ]]; then
    echo "  Result:   MATCH"
else
    echo "  Result:   MISMATCH"
    PASS=false
fi

echo ""
echo "TEE-T:"
echo "  Expected: ${EXPECTED_TT}"
echo "  Actual:   ${ACTUAL_TT}"
if [[ "${EXPECTED_TT}" == "${ACTUAL_TT}" ]]; then
    echo "  Result:   MATCH"
else
    echo "  Result:   MISMATCH"
    PASS=false
fi

echo "============================================="
VERIFIED=$((VERIFIED + 2))
fi

# ---------------------------------------------------------------------------
# SNP app bundles are cross-cloud. Rebuild each recorded source commit with
# its app toolchain and CA bundle, without building or signing a base image.
# ---------------------------------------------------------------------------
SNP_BUILD="${REPO_ROOT}/deploy/snp-build.sh"
if [[ -s "${VERIFY_DIR}/snp-apps" ]]; then
    if [[ ! -x "${SNP_BUILD}" ]]; then
        log "ERROR: SNP app builder is missing or not executable: ${SNP_BUILD}"
        exit 1
    fi
    while read -r ROLE COMMIT EXP_APP; do
        log "Verifying SNP app (tee_${ROLE} @ ${COMMIT:0:12})..."
        git -C "${REPO_ROOT}" rev-parse --verify "${COMMIT}^{commit}" >/dev/null 2>&1 || { log "ERROR: sourceCommit ${COMMIT} not in repo"; PASS=false; continue; }
        APP_LOG="${VERIFY_DIR}/snp-app-${ROLE}.log"
        # SNP_BUILD_COMMIT makes snp-build.sh create a real clone of the recorded
        # source commit, use that commit's app pins, and embed the same VCS stamp
        # as the fleet build. App-only mode needs no deployment configuration.
        if ! SNP_BUILD_COMMIT="${COMMIT}" SNP_EXPECT_DIGEST="${EXP_APP}" \
            "${SNP_BUILD}" --app-only "${ROLE}" >"${APP_LOG}" 2>&1; then
            log "ERROR: SNP app build failed for tee_${ROLE}"
            tail -25 "${APP_LOG}" | sed 's/^/    /'
            PASS=false
            continue
        fi
        ACT_APP=$(sed -n 's/^\[build\]   app digest = \(snp-app:[0-9a-f]\{64\}\)  .*/\1/p' "${APP_LOG}")
        echo "SNP app tee_${ROLE}: expected ${EXP_APP:0:24}… actual ${ACT_APP:0:24}…"
        if [[ "${ACT_APP}" != "${EXP_APP}" ]]; then
            echo "  Result:   MISMATCH — snp-build.sh output (tail):"
            tail -25 "${APP_LOG}" | sed 's/^/    /'
            PASS=false
        else echo "  Result:   MATCH"; fi
        VERIFIED=$((VERIFIED + 1))
    done <"${VERIFY_DIR}/snp-apps"
    echo "============================================="
fi

while read -r CLOUD BASE_DIGEST; do
    log "Verifying signed SNP base (${CLOUD}, ${BASE_DIGEST})..."
    BASE_LOG="${VERIFY_DIR}/snp-base-${CLOUD}.log"
    BASE_ARGS=("${CLOUD}")
    if [[ "${TARGETED}" == true ]]; then BASE_ARGS+=("${BASE_DIGEST}"); fi
    if ! "${SCRIPT_DIR}/snp-base.sh" verify "${BASE_ARGS[@]}" >"${BASE_LOG}" 2>&1; then
        log "ERROR: SNP base verification failed for ${CLOUD}"
        tail -30 "${BASE_LOG}" | sed 's/^/    /'
        PASS=false
        continue
    fi
    log "SNP base ${CLOUD}: signature, image SHA-256, and PCR 11 match"
    VERIFIED=$((VERIFIED + 1))
done <"${VERIFY_DIR}/snp-bases"

if [[ "${VERIFIED}" == 0 ]]; then
    log "ERROR: No images or app bundles were verified"
    exit 1
fi

if [[ "${PASS}" == "true" ]]; then
    echo "VERIFICATION PASSED: ${VERIFIED} images/app bundles match recorded source code"
    exit 0
else
    echo "VERIFICATION FAILED: Images do not match source code"

    # Dump CS debug info only when CS images were built.
    if [[ "${CS_COUNT}" != 0 ]]; then
    echo ""
    echo "=== DEBUG: TEE-K OCI manifest ==="
    cat "${VERIFY_DIR}/tee-k-oci/index.json" 2>/dev/null | python3 -m json.tool || true

    echo ""
    echo "=== DEBUG: TEE-K config ==="
    MANIFEST_DIGEST=$(python3 -c "import json; print(json.load(open('${VERIFY_DIR}/tee-k-oci/index.json'))['manifests'][0]['digest'].split(':')[1])" 2>/dev/null || true)
    if [[ -n "${MANIFEST_DIGEST}" ]]; then
        cat "${VERIFY_DIR}/tee-k-oci/blobs/sha256/${MANIFEST_DIGEST}" 2>/dev/null | python3 -m json.tool || true
    fi

    echo ""
    echo "=== DEBUG: TEE-K layer listing ==="
    find "${VERIFY_DIR}/tee-k-oci/blobs" -type f -exec sha256sum {} \; 2>/dev/null | sort || true

    echo ""
    echo "=== DEBUG: BuildKit worker info ==="
    docker exec buildx_buildkit_reclaim-repro0 cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ' || true
    echo ""

    # Save tarballs for artifact upload
    mkdir -p /tmp/verify-debug
    cp "${VERIFY_DIR}"/tee-*.tar /tmp/verify-debug/ 2>/dev/null || true
    fi

    exit 1
fi
