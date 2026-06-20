#!/bin/bash
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true

# =============================================================================
# Isolated TEST router for the SEV-SNP cross-cloud work. Mirrors prod (Cloud Run
# + global external HTTPS LB) but shares NOTHING with prod:
#   - separate Firestore database (isolated, not the prod DB)
#   - LocalSigner (no KMS key) + min-instances=1 for a stable JWT pubkey
#   - own runtime SA, own ADMIN_TOKEN, own JWT_ISSUER
#   - own global IP + domain
# All deployment-specific values (project, domain, names) live in deploy/.env.
# Prod router/TEEs/DB/KMS are never touched.
#
#   ./deploy/snp-test-router.sh db       create the isolated Firestore database
#   ./deploy/snp-test-router.sh build    build+push the router image (tag snp-test)
#   ./deploy/snp-test-router.sh deploy    deploy the test router Cloud Run service
#   ./deploy/snp-test-router.sh lb        build the HTTPS LB (NEG/backend/cert/proxy/fwd)
#   ./deploy/snp-test-router.sh status    cert + healthz over the domain
#   ./deploy/snp-test-router.sh down      delete LB + service (keeps DB + IP)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
P="${GCP_PROJECT:?set GCP_PROJECT in deploy/.env}"
REGION="${SNP_TEST_REGION:?set SNP_TEST_REGION in deploy/.env}"
DOMAIN="${SNP_TEST_DOMAIN:?set SNP_TEST_DOMAIN in deploy/.env}"
SERVICE="${SNP_TEST_SERVICE:?set SNP_TEST_SERVICE in deploy/.env}"
DB="${SNP_TEST_DB:?set SNP_TEST_DB in deploy/.env}"
RUNTIME_SA="${SNP_TEST_RUNTIME_SA_NAME:?set SNP_TEST_RUNTIME_SA_NAME in deploy/.env}@${P}.iam.gserviceaccount.com"
IMAGE="${REGION}-docker.pkg.dev/${P}/${ROUTER_AR_REPO:-router}/router:snp-test"
ADDR="${SNP_TEST_ADDR:?set SNP_TEST_ADDR in deploy/.env}"
ADMIN_TOKEN_FILE="${SCRIPT_DIR}/.${SERVICE}-admin-token"

g() { gcloud "$@" --project="$P"; }

cmd_db() {
    g firestore databases create --database="$DB" --location="$REGION" --type=firestore-native 2>&1 | tail -3 || true
    g iam service-accounts create "${SNP_TEST_RUNTIME_SA_NAME}" --display-name="Test router (SNP) runtime" 2>&1 | tail -1 || true
    g projects add-iam-policy-binding "$P" --member="serviceAccount:${RUNTIME_SA}" --role="roles/datastore.user" --condition=None >/dev/null
    echo "[db] database ${DB} + runtime SA ready"
}

cmd_build() {
    local yaml; yaml="$(mktemp --suffix=.yaml)"
    cat > "$yaml" <<EOF
steps:
- name: gcr.io/cloud-builders/docker
  args: ['build', '-f', 'router/Dockerfile', '-t', '${IMAGE}', '.']
images:
- '${IMAGE}'
EOF
    ( cd "$REPO_ROOT" && g builds submit --config="$yaml" . )
    rm -f "$yaml"
}

cmd_deploy() {
    local token
    if [[ -f "$ADMIN_TOKEN_FILE" ]]; then token="$(cat "$ADMIN_TOKEN_FILE")"; else
        token="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"; echo "$token" > "$ADMIN_TOKEN_FILE"; fi
    # Persistent local JWT signing key (single-line \n-escaped PEM) so the
    # router's pubkey survives restarts; without it LocalSigner regenerates.
    local signkey="${SCRIPT_DIR}/.${SERVICE}-signing-key"
    [[ -f "$signkey" ]] || { echo "missing ${signkey} (generate with: openssl ecparam -genkey -name prime256v1 -noout | awk '{printf \"%s\\\\n\",\$0}')" >&2; exit 1; }
    local sk; sk="$(cat "$signkey")"
    g run deploy "$SERVICE" --region="$REGION" --image="$IMAGE" \
        --service-account="$RUNTIME_SA" --min-instances=1 --allow-unauthenticated \
        --set-env-vars="^|^FIRESTORE_PROJECT_ID=${P}|FIRESTORE_DATABASE_ID=${DB}|JWT_ISSUER=${SNP_JWT_ISSUER}|JWT_SIGNING_KEY=${sk}|ADMIN_TOKEN=${token}|SA_TOKEN_AUDIENCE=https://${DOMAIN}|APPROVED_SA_PATTERN=^tee-[kt]-sa@${P}\.iam\.gserviceaccount\.com\$|TEE_K_SA_EMAIL=${TEE_K_SA}|TEE_T_SA_EMAIL=${TEE_T_SA}" \
        --quiet
    echo "[deploy] ADMIN_TOKEN in ${ADMIN_TOKEN_FILE}"
}

cmd_lb() {
    g compute network-endpoint-groups create ${SERVICE}-neg --region="$REGION" \
        --network-endpoint-type=serverless --cloud-run-service="$SERVICE" 2>&1 | tail -1 || true
    g compute backend-services create ${SERVICE}-backend --global --load-balancing-scheme=EXTERNAL_MANAGED 2>&1 | tail -1 || true
    g compute backend-services add-backend ${SERVICE}-backend --global \
        --network-endpoint-group=${SERVICE}-neg --network-endpoint-group-region="$REGION" 2>&1 | tail -1 || true
    g compute url-maps create ${SERVICE}-urlmap --default-service=${SERVICE}-backend --global 2>&1 | tail -1 || true
    g compute ssl-certificates create ${SERVICE}-cert --domains="$DOMAIN" --global 2>&1 | tail -1 || true
    g compute target-https-proxies create ${SERVICE}-https-proxy --url-map=${SERVICE}-urlmap --ssl-certificates=${SERVICE}-cert --global 2>&1 | tail -1 || true
    g compute forwarding-rules create ${SERVICE}-fwd --global \
        --target-https-proxy=${SERVICE}-https-proxy --address="$ADDR" --ports=443 \
        --load-balancing-scheme=EXTERNAL_MANAGED 2>&1 | tail -1 || true
}

cmd_status() {
    echo "cert: $(g compute ssl-certificates describe ${SERVICE}-cert --global --format='value(managed.status)')"
    curl -s -o /tmp/tr -w "https://${DOMAIN}/healthz -> %{http_code}\n" --max-time 12 "https://${DOMAIN}/healthz" || true
    cat /tmp/tr 2>/dev/null; echo
}

cmd_down() {
    g compute forwarding-rules delete ${SERVICE}-fwd --global --quiet 2>/dev/null || true
    g compute target-https-proxies delete ${SERVICE}-https-proxy --global --quiet 2>/dev/null || true
    g compute ssl-certificates delete ${SERVICE}-cert --global --quiet 2>/dev/null || true
    g compute url-maps delete ${SERVICE}-urlmap --global --quiet 2>/dev/null || true
    g compute backend-services delete ${SERVICE}-backend --global --quiet 2>/dev/null || true
    g compute network-endpoint-groups delete ${SERVICE}-neg --region="$REGION" --quiet 2>/dev/null || true
    g run services delete "$SERVICE" --region="$REGION" --quiet 2>/dev/null || true
    echo "[down] LB + service deleted (Firestore DB ${DB} + IP ${ADDR} kept)"
}

case "${1:-}" in
    db) cmd_db ;;
    build) cmd_build ;;
    deploy) cmd_deploy ;;
    lb) cmd_lb ;;
    status) cmd_status ;;
    down) cmd_down ;;
    *) echo "usage: $0 {db|build|deploy|lb|status|down}" >&2; exit 1 ;;
esac
