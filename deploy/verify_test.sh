#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT
trap 'cat "${TEST_DIR}/output.log" >&2' ERR
REPO="${TEST_DIR}/repo"
MOCK_BIN="${TEST_DIR}/bin"
mkdir -p "${REPO}/deploy/snp-image" "${MOCK_BIN}" "${TEST_DIR}/mpc/pkg"
cp "${SCRIPT_DIR}/verify.sh" "${SCRIPT_DIR}/snp-build.sh" "${SCRIPT_DIR}/_lib.sh" "${REPO}/deploy/"
cp "${SCRIPT_DIR}/snp-image/"{app-pins,source-commit}.sh "${REPO}/deploy/snp-image/"
cp "${SCRIPT_DIR}/snp-image/base-history.py" "${REPO}/deploy/snp-image/"
cat >"${REPO}/deploy/snp-base.sh" <<'MOCK'
#!/bin/bash
set -euo pipefail
[[ "$1" == verify ]]
echo "base $2" >>"${MOCK_CALLS}"
[[ "${MOCK_FAIL_BASE:-}" != "$2" ]] || { echo 'base signature failed' >&2; exit 25; }
echo "[base] VERIFIED $2"
MOCK
chmod +x "${REPO}/deploy/"*.sh
printf 'circuit\n' >"${TEST_DIR}/mpc/pkg/circuit"
printf '%s\n' 'deploy/image-history.json' 'deploy/.env' 'deploy/snp-image/app-bundle.tar' \
    'deploy/snp-image/mkosi.extra/' >"${REPO}/.gitignore"
export MOCK_CA="alpine@sha256:$(printf 'a%.0s' {1..64})"
printf 'SNP_TEE_GO_TOOLCHAIN="go1.26.5"\nSNP_CA_IMAGE="%s"\n' "${MOCK_CA}" >"${REPO}/deploy/snp-image/pins.env"
git -C "${REPO}" init -q
git -C "${REPO}" add .
git -C "${REPO}" -c user.name=Test -c user.email=test@example.com commit -qm source
export MOCK_COMMIT="$(git -C "${REPO}" rev-parse HEAD)"
# Current pins differ from the recorded source. Rebuilds must use the old pins.
printf 'SNP_TEE_GO_TOOLCHAIN="go1.27.0"\nSNP_CA_IMAGE="alpine@sha256:%s"\n' \
    "$(printf 'b%.0s' {1..64})" >"${REPO}/deploy/snp-image/pins.env"
git -C "${REPO}" add .
git -C "${REPO}" -c user.name=Test -c user.email=test@example.com commit -qm current
export MOCK_CALLS="${TEST_DIR}/calls" MOCK_MPC="${TEST_DIR}/mpc"
export MOCK_CS_K="sha256:$(printf 'c%.0s' {1..64})" MOCK_CS_T="sha256:$(printf 'd%.0s' {1..64})"
unset GCP_PROJECT SNP_BUILD_COMMIT SNP_BUILD_ONLY SNP_EXPECT_DIGEST SNP_ALLOW_DIRTY DOCKER || true

cat >"${MOCK_BIN}/go" <<'MOCK'
#!/bin/bash
set -euo pipefail
[[ "${GOTOOLCHAIN}" == go1.26.5 ]]
[[ "$(git rev-parse HEAD)" == "${MOCK_COMMIT}" ]]
[[ -z "$(git status --porcelain)" ]]
case "$1" in
    build)
        role="${!#}"
        [[ "${role}" == ./tee_k || "${role}" == ./tee_t ]]
        echo "app ${role}" >>"${MOCK_CALLS}"
        [[ "${MOCK_FAIL_ROLE:-}" != "${role}" ]] || { echo 'compiler failed' >&2; exit 23; }
        while [[ "$1" != -o ]]; do shift; done
        printf 'app %s from %s\n' "${role}" "${MOCK_COMMIT}" >"$2"
        ;;
    list) printf '%s\n' "${MOCK_MPC}" ;;
    *) echo "unexpected go invocation: $*" >&2; exit 1 ;;
esac
MOCK
cat >"${MOCK_BIN}/docker" <<'MOCK'
#!/bin/bash
set -euo pipefail
case "$1 $2" in
    'run --rm')
        [[ "$3" == "${MOCK_CA}" ]]
        [[ "$4 $5" == 'cat /etc/ssl/certs/ca-certificates.crt' ]]
        [[ "${MOCK_FAIL_CA:-0}" != 1 ]] || { echo 'CA extraction failed' >&2; exit 24; }
        printf 'test CA bundle\n'
        ;;
    'buildx inspect') exit 0 ;;
    'buildx build')
        while [[ "$1" != -o ]]; do shift; done
        dest="${2#type=oci,dest=}"; dest="${dest%,rewrite-timestamp=true}"
        case "${dest}" in
            */tee-k.tar) digest="${MOCK_CS_K}" ;;
            */tee-t.tar) digest="${MOCK_CS_T}" ;;
            *) exit 1 ;;
        esac
        echo "cs ${digest}" >>"${MOCK_CALLS}"
        oci="$(mktemp -d)"
        printf '{"manifests":[{"digest":"%s"}]}\n' "${digest}" >"${oci}/index.json"
        tar -C "${oci}" -cf "${dest}" index.json
        rm -rf "${oci}"
        ;;
    *) echo "unexpected docker invocation: $*" >&2; exit 1 ;;
esac
MOCK
chmod +x "${MOCK_BIN}/"*
export PATH="${MOCK_BIN}:${PATH}"

# Compute expected bundles independently, including the tar metadata contract.
expected_app() {
    local role="$1" stage="${TEST_DIR}/expected-${1}"
    mkdir -p "${stage}/mpcl/pkg" "${stage}/etc/ssl/certs"
    printf 'app ./tee_%s from %s\n' "${role}" "${MOCK_COMMIT}" >"${stage}/app"
    printf 'circuit\n' >"${stage}/mpcl/pkg/circuit"
    printf 'test CA bundle\n' >"${stage}/etc/ssl/certs/ca-certificates.crt"
    find "${stage}" -type d -exec chmod 0755 {} +
    find "${stage}" -type f -exec chmod 0644 {} +
    chmod 0755 "${stage}/app"
    tar --sort=name --format=gnu --mtime=@1735689600 --owner=0 --group=0 --numeric-owner \
        -C "${stage}" -cf "${TEST_DIR}/expected-${role}.tar" .
    printf 'snp-app:%s\n' "$(sha256sum "${TEST_DIR}/expected-${role}.tar" | cut -d' ' -f1)"
}
export MOCK_APP_K="$(expected_app k)" MOCK_APP_T="$(expected_app t)"

write_history() {
    python3 - "${REPO}/deploy/image-history.json" "$1" <<'PY'
import base64, json, os, sys
mode = sys.argv[2]
apps = []
if mode not in ('empty', 'cs-only', 'base-only'):
    for role in ('k', 't'):
        apps.append(dict(type='sev-snp', role=role,
                         sourceCommit=os.environ['MOCK_COMMIT'],
                         version=os.environ['MOCK_APP_' + role.upper()]))
if mode in ('mixed', 'cs-only', 'cs-mismatch'):
    for role in ('k', 't'):
        apps.append(dict(type='cs', package='test/tee-' + role,
                         sourceCommit=os.environ['MOCK_COMMIT'], sourceDateEpoch=1735689600,
                         version=os.environ['MOCK_CS_' + role.upper()]))
if mode == 'mismatch':
    apps[0]['version'] = 'snp-app:' + '0' * 64
if mode == 'missing-role':
    apps.pop()
if mode == 'missing-commit':
    del apps[0]['sourceCommit']
if mode == 'unknown-commit':
    apps[0]['sourceCommit'] = '0' * 40
if mode == 'malformed-digest':
    apps[0]['version'] = 'snp-app:bad'
if mode == 'cs-mismatch':
    apps[-2]['version'] = 'sha256:' + '0' * 64
bases = []
if mode in ('base-only', 'mixed-bases', 'missing-base-signature'):
    for cloud in ('gcp', 'aws'):
        bases.append(dict(cloud=cloud, base='snp-base:' + '1' * (64 if cloud == 'gcp' else 96),
                          base_uki_sha256='2' * 64, sourceCommit=os.environ['MOCK_COMMIT'],
                          kernelCmdline='console=ttyS0,115200',
                          base_uki_signature=base64.b64encode(b'fixture-signature').decode()))
if mode == 'missing-base-signature':
    del bases[-1]['base_uki_signature']
json.dump(dict(base_images=bases, app_images=apps),
          open(sys.argv[1], 'w'))
PY
}

verify_success() {
    : >"${MOCK_CALLS}"
    bash "${REPO}/deploy/verify.sh" >"${TEST_DIR}/output.log" 2>&1
    grep -q 'VERIFICATION PASSED' "${TEST_DIR}/output.log"
}
verify_failure() {
    if bash "${REPO}/deploy/verify.sh" >"${TEST_DIR}/output.log" 2>&1; then
        echo 'verification unexpectedly passed' >&2
        return 1
    fi
    if grep -q 'VERIFICATION PASSED' "${TEST_DIR}/output.log"; then return 1; fi
}

# No private key, public signing assets, loader, or cloud configuration exists.
# App verification must also ignore an operator's deployment environment.
printf 'echo "deployment environment must not be sourced" >&2; exit 99\n' >"${REPO}/deploy/.env"
write_history snp
verify_success
[[ "$(grep -c '^app ' "${MOCK_CALLS}")" == 2 ]]
grep -q 'app ./tee_k' "${MOCK_CALLS}"
grep -q 'app ./tee_t' "${MOCK_CALLS}"
[[ ! -f "${REPO}/deploy/snp-digests.env" ]]
echo 'PASS: SNP-only history verifies both recorded app bundles without signing assets'

write_history mixed
verify_success
[[ "$(grep -c '^app ' "${MOCK_CALLS}")" == 2 ]]
[[ "$(grep -c '^cs ' "${MOCK_CALLS}")" == 2 ]]
write_history cs-only
verify_success
[[ "$(grep -c '^cs ' "${MOCK_CALLS}")" == 2 ]]
echo 'PASS: mixed and CS-only histories preserve CS verification'

write_history base-only
verify_success
[[ "$(grep -c '^base ' "${MOCK_CALLS}")" == 2 ]]
write_history mixed-bases
verify_success
[[ "$(grep -c '^app ' "${MOCK_CALLS}")" == 2 ]]
[[ "$(grep -c '^base ' "${MOCK_CALLS}")" == 2 ]]
export MOCK_FAIL_BASE=aws
verify_failure
grep -q 'base signature failed' "${TEST_DIR}/output.log"
unset MOCK_FAIL_BASE
mv "${REPO}/deploy/snp-base.sh" "${TEST_DIR}/snp-base.sh"
verify_failure
mv "${TEST_DIR}/snp-base.sh" "${REPO}/deploy/snp-base.sh"
echo 'PASS: both base clouds run; failed or missing base builders fail verification'

for mode in empty mismatch missing-role missing-commit unknown-commit malformed-digest cs-mismatch missing-base-signature; do
    write_history "${mode}"
    verify_failure
done
echo 'PASS: empty, incomplete, invalid, and mismatching histories fail'

write_history snp
export MOCK_FAIL_ROLE=./tee_k
verify_failure
grep -q 'compiler failed' "${TEST_DIR}/output.log"
unset MOCK_FAIL_ROLE
export MOCK_FAIL_CA=1
verify_failure
grep -q 'CA extraction failed' "${TEST_DIR}/output.log"
unset MOCK_FAIL_CA
echo 'PASS: compiler and CA extraction failures propagate'

# A failed builder must fail verification even if it prints the expected digest.
mv "${REPO}/deploy/snp-build.sh" "${TEST_DIR}/snp-build.sh"
cat >"${REPO}/deploy/snp-build.sh" <<'MOCK'
#!/bin/bash
if [[ "$2" == k ]]; then digest="${MOCK_APP_K}"; else digest="${MOCK_APP_T}"; fi
echo "[build]   app digest = ${digest}  (commit ${MOCK_COMMIT})"
exit 23
MOCK
chmod +x "${REPO}/deploy/snp-build.sh"
verify_failure
rm "${REPO}/deploy/snp-build.sh"
verify_failure
mv "${TEST_DIR}/snp-build.sh" "${REPO}/deploy/snp-build.sh"
echo 'PASS: failed or missing builder cannot produce a successful verification'

# Full image builds must still require the production signing key.
rm "${REPO}/deploy/.env"
printf '%s\n' 'SNP_LOADER_GO_TOOLCHAIN="go1.27.0"' 'SNP_APT_SNAPSHOT="test"' >>"${REPO}/deploy/snp-image/pins.env"
mkdir -p "${REPO}/deploy/secure-boot"
for public in PK.crt.der KEK.crt.der R.crt.der R.crt.pem R.pub.pem aws-uefi-data.b64; do
    touch "${REPO}/deploy/secure-boot/${public}"
done
if GCP_PROJECT=test SNP_BUILD_ONLY=1 bash "${REPO}/deploy/snp-build.sh" k gcp >"${TEST_DIR}/output.log" 2>&1; then
    echo 'full image build unexpectedly accepted a missing signing key' >&2
    exit 1
fi
grep -q 'missing Secure Boot artifact .*/R.key' "${TEST_DIR}/output.log"
echo 'PASS: full image builds still require R.key'
