#!/bin/bash
# End-to-end test script for Kubewarden + private Sigstore instance.
#
# Runs three sequential stages:
#   1. Setup  — spin up a KinD cluster with the full Sigstore stack
#               (Fulcio, Rekor, CTLog, TUF) and generate trust config files.
#   2. Sign   — copy a test policy to the local registry, sign it with cosign
#               against the private Sigstore instance, then verify with cosign
#               and kwctl.
#   3. Deploy — install Kubewarden from local charts, configure the PolicyServer
#               with the private Sigstore trust root, deploy a ClusterAdmissionPolicy
#               and exercise the webhook to confirm allow/deny behaviour.
#
# Based on: https://github.com/sigstore/scaffolding/blob/main/getting-started.md
# Related:  https://github.com/kubewarden/adm-controller/pull/1485
#
# Usage:
#   ./test-sigstore-e2e.sh [OPTIONS]
#
# Options:
#   --skip-setup          Skip stage 1 (cluster + Sigstore stack setup).
#                         Requires config files to exist in the current directory
#                         and the KinD cluster to already be running.
#   --skip-sign           Skip stage 2 (image copy, cosign sign/verify, kwctl verify).
#                         Assumes the policy is already signed and pushed to the
#                         local registry from a previous run.
#   --skip-kubewarden     Skip stage 3 (Kubewarden install, policy deploy, webhook eval).
#   --no-sigstore         Install Kubewarden in stage 3 without any Sigstore
#                         configuration. Skips policy deployment and webhook evaluation.
#   --policy-server-image Full image reference (repository:tag) for the policy-server.
#                         Overrides the default image in the kubewarden-controller chart.
#                         Example: --policy-server-image ghcr.io/kubewarden/adm-controller/policy-server:dev
#
# Tools required (per stage):
#   All stages:  kubectl, jq
#   Stage 1:     kind, docker, ko, yq, cosign
#   Stage 2:     cosign, skopeo, kwctl
#   Stage 3:     helm, cosign, skopeo (unless --skip-sign was also passed)

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# ── Versions ──────────────────────────────────────────────────────────────────
# renovate: datasource=github-release-attachments depName=sigstore/scaffolding
SCAFFOLDING_VERSION=v0.7.31
# renovate: datasource=github-release-attachments depName=sigstore/scaffolding digestVersion=v0.7.31
SETUP_KIND_SHA256=a739e49ee8f98c8e966a1e6fddf38598acf09cf27ada2a0ebb3901fd366cecad
# renovate: datasource=github-release-attachments depName=sigstore/scaffolding digestVersion=v0.7.31
SETUP_SCAFFOLDING_SHA256=8861da880cb8f4ddc22fb83e92975dd6744bd6cea8f1d4025183d740ddbb2222

# ── Image references ──────────────────────────────────────────────────────────
SOURCE_POLICY_IMAGE=ghcr.io/kubewarden/tests/pod-privileged:v0.2.5
# The registry container listens on port 5001, reachable from both the host
# and from inside the KinD cluster.
TEST_POLICY_IMAGE=registry.local:5001/policies/testing:latest

# ── Kubewarden config ─────────────────────────────────────────────────────────
KUBEWARDEN_NAMESPACE=kubewarden
SIGSTORE_TRUST_CONFIGMAP=sigstore-trust-config
VERIFICATION_CONFIGMAP=verification-config
TEST_POLICY_NAME=test-sigstore-policy

# ── Service URLs (populated by setup_env_vars or read_service_urls) ───────────
REKOR_URL=""
FULCIO_URL=""
CTLOG_URL=""
TSA_URL=""
TUF_MIRROR=""
ISSUER_URL=""

# ── CLI flags ─────────────────────────────────────────────────────────────────
SKIP_SETUP=false
SKIP_SIGN=false
SKIP_KUBEWARDEN=false
NO_SIGSTORE=false
POLICY_SERVER_IMAGE=""

# ── Cleanup ───────────────────────────────────────────────────────────────────
function cleanup() {
    rm -f /tmp/setup-kind.sh /tmp/setup-scaffolding-from-release.sh
    # Keep all cluster resources intact so the developer can inspect state.
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════════════════
# Prerequisites
# ══════════════════════════════════════════════════════════════════════════════

function check_prerequisites() {
    # Build the required tools list based on which stages are active.
    local tools=("kubectl" "jq")

    if [[ "${SKIP_SETUP}" == "false" ]]; then
        tools+=("kind" "docker" "ko" "yq" "cosign")
    fi

    if [[ "${SKIP_SIGN}" == "false" ]]; then
        tools+=("cosign" "skopeo" "kwctl")
    fi

    if [[ "${SKIP_KUBEWARDEN}" == "false" ]]; then
        tools+=("helm")
    fi

    # Deduplicate
    local unique_tools
    mapfile -t unique_tools < <(printf '%s\n' "${tools[@]}" | sort -u)

    local missing=()
    for tool in "${unique_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}ERROR: The following required tools are not installed:${NC}"
        for t in "${missing[@]}"; do
            echo -e "  - ${RED}${t}${NC}"
        done
        echo ""
        echo "Install instructions:"
        echo "  kind:    https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
        echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  docker:  https://docs.docker.com/get-docker/"
        echo "  ko:      go install github.com/ko-build/ko/cmd/ko@v0.18.1"
        echo "  yq:      go install github.com/mikefarah/yq/v4@v4.52.5"
        echo "  cosign:  https://docs.sigstore.dev/cosign/system_config/installation/"
        echo "  skopeo:  https://github.com/containers/skopeo/blob/main/install.md"
        echo "  kwctl:   https://github.com/kubewarden/kwctl#installation"
        echo "  helm:    https://helm.sh/docs/intro/install/"
        echo "  jq:      https://jqlang.github.io/jq/download/"
        exit 1
    fi

    echo -e "${GREEN}All prerequisites satisfied.${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1 — Setup Sigstore environment
# ══════════════════════════════════════════════════════════════════════════════

function setup_kind_cluster() {
    echo -e "${GREEN}Setting up KinD cluster with Knative (scaffolding ${SCAFFOLDING_VERSION})...${NC}"

    # Remove stale registry container from a previous run, if any
    docker rm -f "$(docker ps -aq --filter ancestor=registry:2)" 2>/dev/null || true

    curl -fLo /tmp/setup-kind.sh \
        "https://github.com/sigstore/scaffolding/releases/download/${SCAFFOLDING_VERSION}/setup-kind.sh"
    echo "${SETUP_KIND_SHA256}  /tmp/setup-kind.sh" | sha256sum -c - || exit 1
    chmod u+x /tmp/setup-kind.sh
    /tmp/setup-kind.sh
}

function install_sigstore_scaffolding() {
    echo -e "${GREEN}Installing Sigstore scaffolding (Fulcio, Rekor, CTLog, TUF)...${NC}"

    export KO_DOCKER_REPO=registry.local:5001/sigstore

    curl -fLo /tmp/setup-scaffolding-from-release.sh \
        "https://github.com/sigstore/scaffolding/releases/download/${SCAFFOLDING_VERSION}/setup-scaffolding-from-release.sh"
    echo "${SETUP_SCAFFOLDING_SHA256}  /tmp/setup-scaffolding-from-release.sh" | sha256sum -c - || exit 1
    chmod u+x /tmp/setup-scaffolding-from-release.sh
    /tmp/setup-scaffolding-from-release.sh
}

function setup_env_vars() {
    # Read the sslip.io URLs assigned to each Knative service by scaffolding.
    # These DNS names resolve via MetalLB's LoadBalancer IP and work from both
    # the host machine and inside the cluster.
    echo -e "${GREEN}Reading service URLs from cluster...${NC}"
    REKOR_URL=$(kubectl -n rekor-system  get ksvc rekor  -ojsonpath='{.status.url}')
    export REKOR_URL
    FULCIO_URL=$(kubectl -n fulcio-system get ksvc fulcio -ojsonpath='{.status.url}')
    export FULCIO_URL
    CTLOG_URL=$(kubectl -n ctlog-system  get ksvc ctlog  -ojsonpath='{.status.url}')
    export CTLOG_URL
    TSA_URL=$(kubectl -n tsa-system      get ksvc tsa    -ojsonpath='{.status.url}')
    export TSA_URL
    TUF_MIRROR=$(kubectl -n tuf-system   get ksvc tuf    -ojsonpath='{.status.url}')
    export TUF_MIRROR
    # gettoken is optional — not installed by the default scaffolding setup
    ISSUER_URL=$(kubectl -n default get ksvc gettoken -ojsonpath='{.status.url}' 2>/dev/null || true)
    export ISSUER_URL

    echo -e "${GREEN}  REKOR_URL=${REKOR_URL}${NC}"
    echo -e "${GREEN}  FULCIO_URL=${FULCIO_URL}${NC}"
    echo -e "${GREEN}  CTLOG_URL=${CTLOG_URL}${NC}"
    echo -e "${GREEN}  TSA_URL=${TSA_URL}${NC}"
    echo -e "${GREEN}  TUF_MIRROR=${TUF_MIRROR}${NC}"
    if [[ -n "${ISSUER_URL}" ]]; then
        echo -e "${GREEN}  ISSUER_URL=${ISSUER_URL}${NC}"
    else
        echo -e "${YELLOW}  ISSUER_URL=(not available — gettoken ksvc not found)${NC}"
    fi
}

function generate_config_files() {
    echo -e "${GREEN}Generating Sigstore config files...${NC}"

    curl --fail -o "fulcio.pem" "${FULCIO_URL}/api/v1/rootCert"
    curl --fail -o "rekor.pub"  "${REKOR_URL}/api/v1/log/publicKey"
    curl --fail -o "tsa.pem"    "${TSA_URL}/api/v1/timestamp/certchain"
    kubectl get secret -o json -n tuf-system ctlog-public-key \
        | jq -r ".data.public" | base64 -d > ctfe.pub

    cosign trusted-root create \
        --fulcio="url=${FULCIO_URL},certificate-chain=fulcio.pem" \
        --rekor="url=${REKOR_URL},public-key=rekor.pub,start-time=2020-01-01T00:00:00Z" \
        --tsa="url=${TSA_URL},certificate-chain=tsa.pem" \
        --ctfe="url=${CTLOG_URL},public-key=ctfe.pub,start-time=2020-01-01T00:00:00Z" \
        --out trusted_root.json

    local oidc_flag=""
    if [[ -n "${ISSUER_URL}" ]]; then
        oidc_flag="--oidc-provider=url=${ISSUER_URL}/auth,api-version=1,start-time=2020-01-01T00:00:00Z,operator=sigstore.dev"
    fi
    cosign signing-config create \
        --fulcio="url=${FULCIO_URL},api-version=1,start-time=2020-01-01T00:00:00Z,operator=sigstore.dev" \
        --rekor="url=${REKOR_URL},api-version=1,start-time=2020-01-01T00:00:00Z,operator=sigstore.dev" \
        --rekor-config="ANY" \
        ${oidc_flag:+"${oidc_flag}"} \
        --tsa="url=${TSA_URL}/api/v1/timestamp,api-version=1,start-time=2020-01-01T00:00:00Z,operator=sigstore.dev" \
        --tsa-config="EXACT:1" \
        --out signing_config.json

    cat > trust_config.json <<EOF
{
  "mediaType": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json",
  "trustedRoot": $(cat trusted_root.json),
  "signingConfig": $(cat signing_config.json)
}
EOF

    cat > verification_config.yaml <<EOF
allOf:
  - kind: genericIssuer
    issuer: https://kubernetes.default.svc.cluster.local
    subject:
      equal: https://kubernetes.io/namespaces/default/serviceaccounts/default
anyOf: null
EOF

    cat > sources.yaml <<EOF
insecure_sources:
  - registry.local:5001
EOF

    echo -e "${GREEN}Generated: trusted_root.json, signing_config.json, trust_config.json, verification_config.yaml, sources.yaml${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Helpers used when --skip-setup is passed
# ══════════════════════════════════════════════════════════════════════════════

function check_required_files() {
    echo -e "${GREEN}Checking required config files in current directory...${NC}"

    local missing_files=()
    for f in trusted_root.json trust_config.json verification_config.yaml sources.yaml; do
        if [[ ! -f "$f" ]]; then
            missing_files+=("$f")
        fi
    done

    if [[ ${#missing_files[@]} -gt 0 ]]; then
        echo -e "${RED}ERROR: The following required files are missing:${NC}"
        for f in "${missing_files[@]}"; do
            echo -e "  - ${RED}${f}${NC}"
        done
        echo ""
        echo "Run without --skip-setup to generate them, or run:"
        echo "  ./scripts/test-sigstore-e2e.sh  (stage 1 only: use --skip-sign --skip-kubewarden)"
        exit 1
    fi

    echo -e "${GREEN}  All required files found.${NC}"
}

function read_service_urls() {
    # Used when --skip-setup is passed but stage 2 or 3 is active.
    echo -e "${GREEN}Reading service URLs from cluster...${NC}"

    REKOR_URL=$(kubectl -n rekor-system  get ksvc rekor  -ojsonpath='{.status.url}')
    export REKOR_URL
    FULCIO_URL=$(kubectl -n fulcio-system get ksvc fulcio -ojsonpath='{.status.url}')
    export FULCIO_URL
    ISSUER_URL=$(kubectl -n default get ksvc gettoken -ojsonpath='{.status.url}' 2>/dev/null || true)
    export ISSUER_URL

    if [[ -z "${REKOR_URL}" || -z "${FULCIO_URL}" ]]; then
        echo -e "${RED}ERROR: Could not read Rekor or Fulcio URLs from the cluster.${NC}"
        echo "Ensure the Sigstore stack is running (run without --skip-setup)."
        exit 1
    fi

    echo -e "${GREEN}  REKOR_URL=${REKOR_URL}${NC}"
    echo -e "${GREEN}  FULCIO_URL=${FULCIO_URL}${NC}"
    if [[ -n "${ISSUER_URL}" ]]; then
        echo -e "${GREEN}  ISSUER_URL=${ISSUER_URL}${NC}"
    else
        echo -e "${YELLOW}  ISSUER_URL=(gettoken ksvc not found — will use kubectl create token)${NC}"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2 — Sign and verify policy
# ══════════════════════════════════════════════════════════════════════════════

function copy_image() {
    echo -e "${GREEN}Copying ${SOURCE_POLICY_IMAGE} → ${TEST_POLICY_IMAGE}...${NC}"
    skopeo copy --dest-tls-verify=false \
        "docker://${SOURCE_POLICY_IMAGE}" \
        "docker://${TEST_POLICY_IMAGE}"
    echo -e "${GREEN}  Image copied successfully.${NC}"
}

function get_oidc_token() {
    echo -e "${GREEN}Obtaining OIDC token...${NC}"

    if [[ -n "${ISSUER_URL}" ]]; then
        echo -e "${GREEN}  Fetching token from gettoken service...${NC}"
        OIDC_TOKEN=$(curl --fail -s "${ISSUER_URL}")
    else
        echo -e "${GREEN}  Generating token via kubectl create token...${NC}"
        OIDC_TOKEN=$(kubectl create token default \
            -n default \
            --duration=10m \
            --audience=sigstore)
    fi

    export OIDC_TOKEN
    echo -e "${GREEN}  Token obtained.${NC}"
}

function sign_image() {
    echo -e "${GREEN}Signing ${TEST_POLICY_IMAGE} with private Sigstore...${NC}"

    # --new-bundle-format=false: the sigstore Rust crate in policy-server does
    #   not yet support the new bundle format.
    # --use-signing-config=false: use explicit --rekor-url/--fulcio-url rather
    #   than signing_config.json so cosign doesn't pick up public Sigstore URLs.
    cosign sign --yes \
        --rekor-url "${REKOR_URL}" \
        --fulcio-url "${FULCIO_URL}" \
        --allow-insecure-registry \
        --new-bundle-format=false \
        --use-signing-config=false \
        --trusted-root trusted_root.json \
        --identity-token "${OIDC_TOKEN}" \
        "${TEST_POLICY_IMAGE}"

    echo -e "${GREEN}  Image signed successfully.${NC}"
}

function verify_image_cosign() {
    echo -e "${GREEN}Verifying signature on ${TEST_POLICY_IMAGE} with cosign...${NC}"

    cosign verify \
        --new-bundle-format=false \
        --rekor-url "${REKOR_URL}" \
        --allow-insecure-registry \
        --trusted-root trusted_root.json \
        --certificate-identity \
            "https://kubernetes.io/namespaces/default/serviceaccounts/default" \
        --certificate-oidc-issuer \
            "https://kubernetes.default.svc.cluster.local" \
        "${TEST_POLICY_IMAGE}"

    echo -e "${GREEN}  cosign verification passed.${NC}"
}

function verify_image_kwctl() {
    # kwctl uses trust_config.json (ClientTrustConfig: trustedRoot + signingConfig)
    # and verification_config.yaml for Kubewarden admission constraints.
    # sources.yaml declares registry.local:5001 as insecure so kwctl reaches it
    # over plain HTTP without TLS errors.
    echo -e "${GREEN}Verifying policy with kwctl...${NC}"

    kwctl verify \
        --sigstore-trust-config trust_config.json \
        --verification-config-path verification_config.yaml \
        --sources-path sources.yaml \
        "registry://${TEST_POLICY_IMAGE}"

    echo -e "${GREEN}  kwctl verification passed.${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Stage 3 — Install and test Kubewarden
# ══════════════════════════════════════════════════════════════════════════════

function install_kubewarden() {
    echo -e "${GREEN}Installing Kubewarden from local charts...${NC}"

    kubectl create namespace "$KUBEWARDEN_NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo -e "${GREEN}  Installing kubewarden-controller (unified chart)...${NC}"
    helm upgrade --install kubewarden-controller ./charts/admission-controller \
        -n "$KUBEWARDEN_NAMESPACE" \
        --set replicas=1 \
        --wait

    echo -e "${GREEN}  Waiting for admission-controller rollout...${NC}"
    kubectl rollout status deployment/kubewarden-controller-admission-controller \
        -n "$KUBEWARDEN_NAMESPACE" --timeout=3m
}

function build_image_flags() {
    # Populates the IMAGE_FLAGS array with helm --set args for a custom
    # policy-server image when POLICY_SERVER_IMAGE is set.
    IMAGE_FLAGS=()
    if [[ -n "${POLICY_SERVER_IMAGE}" ]]; then
        IMAGE_FLAGS+=(--set "policyServer.image.repository=${POLICY_SERVER_IMAGE%:*}")
        IMAGE_FLAGS+=(--set "policyServer.image.tag=${POLICY_SERVER_IMAGE##*:}")
    fi
}

function configure_policy_server() {
    echo -e "${GREEN}Configuring PolicyServer with private Sigstore...${NC}"

    echo -e "${GREEN}  Creating sigstore-trust-config ConfigMap...${NC}"
    kubectl create configmap "$SIGSTORE_TRUST_CONFIGMAP" \
        --from-file=sigstore-trust-config=trust_config.json \
        -n "$KUBEWARDEN_NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo -e "${GREEN}  Creating verification-config ConfigMap...${NC}"
    kubectl create configmap "$VERIFICATION_CONFIGMAP" \
        --from-file=verification-config=verification_config.yaml \
        -n "$KUBEWARDEN_NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo -e "${GREEN}  Upgrading kubewarden-controller with default PolicyServer and Sigstore config...${NC}"
    local image_flags=()
    build_image_flags
    image_flags=("${IMAGE_FLAGS[@]}")

    helm upgrade --install kubewarden-controller ./charts/admission-controller \
        -n "$KUBEWARDEN_NAMESPACE" \
        --set replicas=1 \
        --set 'policyServer.sigstoreTrustConfig'="$SIGSTORE_TRUST_CONFIGMAP" \
        --set 'policyServer.verificationConfig'="$VERIFICATION_CONFIGMAP" \
        --set 'policyServer.insecureSources[0]=registry.local:5001' \
        --set 'policyServer.env[0].name=KUBEWARDEN_LOG_LEVEL' \
        --set 'policyServer.env[0].value=info' \
        --set 'policyServer.env[1].name=RUST_BACKTRACE' \
        --set 'policyServer.env[1].value=1' \
        "${image_flags[@]}" \
        --wait
    # Policy-server readiness is confirmed when the ClusterAdmissionPolicy
    # reaches PolicyActive — see deploy_and_verify_policy().
}

function install_kubewarden_no_sigstore() {
    echo -e "${GREEN}Upgrading kubewarden-controller with default PolicyServer (no Sigstore configuration)...${NC}"

    local image_flags=()
    build_image_flags
    image_flags=("${IMAGE_FLAGS[@]}")

    helm upgrade --install kubewarden-controller ./charts/admission-controller \
        -n "$KUBEWARDEN_NAMESPACE" \
        --set replicas=1 \
        --set 'policyServer.env[0].name=KUBEWARDEN_LOG_LEVEL' \
        --set 'policyServer.env[0].value=info' \
        --set 'policyServer.env[1].name=RUST_BACKTRACE' \
        --set 'policyServer.env[1].value=1' \
        "${image_flags[@]}" \
        --wait

    echo -e "${GREEN}  Waiting for default policy-server deployment to be Available...${NC}"
    kubectl wait deployment "policy-server-default" \
        -n "$KUBEWARDEN_NAMESPACE" \
        --for=condition=Available \
        --timeout=5m
}

function deploy_and_verify_policy() {
    echo -e "${GREEN}Deploying test ClusterAdmissionPolicy...${NC}"

    kubectl apply -f - <<EOF
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: ${TEST_POLICY_NAME}
spec:
  module: registry://${TEST_POLICY_IMAGE}
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
        - CREATE
        - UPDATE
  mutating: false
EOF

    echo -e "${GREEN}  Waiting for ClusterAdmissionPolicy to become active...${NC}"
    kubectl wait "clusteradmissionpolicy/${TEST_POLICY_NAME}" \
        --for=condition=PolicyActive \
        --timeout=3m

    echo -e "${GREEN}  Checking policy-server logs for verified-signatures...${NC}"
    local ps_pod
    ps_pod=$(kubectl get pods -n "$KUBEWARDEN_NAMESPACE" \
        -l app=kubewarden-policy-server-default \
        -o jsonpath='{.items[0].metadata.name}')

    if kubectl logs "$ps_pod" -n "$KUBEWARDEN_NAMESPACE" \
            | grep -q "verified-signatures"; then
        echo -e "${GREEN}  ✓ policy-server confirmed signature verification via private Sigstore.${NC}"
    else
        echo -e "${RED}ERROR: 'verified-signatures' not found in policy-server logs.${NC}"
        echo "Policy-server logs:"
        kubectl logs "$ps_pod" -n "$KUBEWARDEN_NAMESPACE" | tail -40
        exit 1
    fi
}

function evaluate_policy_in_cluster() {
    echo -e "${GREEN}Evaluating policy via in-cluster policy-server webhook...${NC}"

    # Test 1: non-privileged pod — must be ALLOWED by the webhook.
    echo -e "${GREEN}  Creating non-privileged pod (expect: ALLOWED)...${NC}"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-non-privileged
  namespace: default
spec:
  containers:
    - name: test
      image: busybox
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
EOF
    echo -e "${GREEN}  ✓ Non-privileged pod was ALLOWED by the policy-server.${NC}"
    kubectl delete pod test-non-privileged -n default --ignore-not-found

    # Test 2: privileged pod — must be DENIED by the webhook.
    # kubectl apply exits non-zero when the webhook denies; capture output and
    # check for denial message without letting set -e abort.
    echo -e "${GREEN}  Creating privileged pod (expect: DENIED)...${NC}"
    local deny_output
    deny_output=$(kubectl apply -f - 2>&1 <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: default
spec:
  containers:
    - name: test
      image: busybox
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
EOF
)
    if echo "${deny_output}" | grep -qi "denied\|violation\|not allowed\|privileged"; then
        echo -e "${GREEN}  ✓ Privileged pod was DENIED by the policy-server.${NC}"
    else
        echo -e "${RED}ERROR: expected privileged pod to be denied. kubectl output:${NC}"
        echo "${deny_output}"
        kubectl delete pod test-privileged -n default --ignore-not-found
        exit 1
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

function print_summary() {
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  Kubewarden + private Sigstore e2e test PASSED${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo -e "${YELLOW}Stages completed:${NC}"
    [[ "${SKIP_SETUP}"     == "false" ]] && echo "  ✓ Stage 1: Sigstore environment setup"
    [[ "${SKIP_SIGN}"      == "false" ]] && echo "  ✓ Stage 2: Policy signed and verified (cosign + kwctl)"
    [[ "${SKIP_KUBEWARDEN}" == "false" && "${NO_SIGSTORE}" == "false" ]] && \
        echo "  ✓ Stage 3: Kubewarden deployed, policy active, webhook allow/deny confirmed"
    [[ "${SKIP_KUBEWARDEN}" == "false" && "${NO_SIGSTORE}" == "true" ]] && \
        echo "  ✓ Stage 3: Kubewarden deployed (no Sigstore configuration)"
    echo ""
    if [[ -n "${REKOR_URL}" ]]; then
        echo -e "${YELLOW}Service URLs:${NC}"
        echo "  REKOR_URL=${REKOR_URL}"
        echo "  FULCIO_URL=${FULCIO_URL}"
        echo ""
    fi
    echo -e "${YELLOW}Policy image:${NC} ${TEST_POLICY_IMAGE}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

function main() {
    # ── Parse CLI flags ────────────────────────────────────────────────────────
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-setup)
                SKIP_SETUP=true
                shift
                ;;
            --skip-sign)
                SKIP_SIGN=true
                shift
                ;;
            --skip-kubewarden)
                SKIP_KUBEWARDEN=true
                shift
                ;;
            --no-sigstore)
                NO_SIGSTORE=true
                shift
                ;;
            --policy-server-image)
                if [[ -z "${2:-}" ]]; then
                    echo -e "${RED}ERROR: --policy-server-image requires a value.${NC}"
                    exit 1
                fi
                POLICY_SERVER_IMAGE="$2"
                shift 2
                ;;
            --help|-h)
                sed -n '/#$/,/^set -euo/{ /^set -euo/d; s/^# \{0,1\}//; p }' "$0"
                exit 0
                ;;
            *)
                echo -e "${RED}ERROR: Unknown argument: $1${NC}"
                echo "Usage: $0 [--skip-setup] [--skip-sign] [--skip-kubewarden] [--no-sigstore] [--policy-server-image <repo:tag>]"
                exit 1
                ;;
        esac
    done

    echo -e "${GREEN}=== Kubewarden + Sigstore end-to-end test ===${NC}"
    [[ -n "${POLICY_SERVER_IMAGE}" ]] && \
        echo -e "${YELLOW}Using custom policy-server image: ${POLICY_SERVER_IMAGE}${NC}"
    echo ""

    check_prerequisites

    # ── Stage 1: Setup Sigstore environment ───────────────────────────────────
    if [[ "${SKIP_SETUP}" == "false" ]]; then
        echo -e "${GREEN}━━━ Stage 1: Setup Sigstore environment ━━━${NC}"
        setup_kind_cluster
        install_sigstore_scaffolding
        setup_env_vars
        generate_config_files
    else
        echo -e "${YELLOW}⏭  Stage 1 skipped (--skip-setup)${NC}"
        # Still need config files and service URLs for subsequent stages.
        if [[ "${SKIP_SIGN}" == "false" || ( "${SKIP_KUBEWARDEN}" == "false" && "${NO_SIGSTORE}" == "false" ) ]]; then
            check_required_files
            read_service_urls
        fi
    fi

    # ── Stage 2: Sign and verify policy ───────────────────────────────────────
    if [[ "${SKIP_SIGN}" == "false" ]]; then
        echo -e "${GREEN}━━━ Stage 2: Sign and verify policy ━━━${NC}"
        copy_image
        get_oidc_token
        sign_image
        verify_image_cosign
        verify_image_kwctl
    else
        echo -e "${YELLOW}⏭  Stage 2 skipped (--skip-sign)${NC}"
    fi

    # ── Stage 3: Install and test Kubewarden ──────────────────────────────────
    if [[ "${SKIP_KUBEWARDEN}" == "false" ]]; then
        if [[ "${NO_SIGSTORE}" == "true" ]]; then
            echo -e "${GREEN}━━━ Stage 3: Install Kubewarden (no Sigstore) ━━━${NC}"
            install_kubewarden
            install_kubewarden_no_sigstore
        else
            echo -e "${GREEN}━━━ Stage 3: Install and test Kubewarden with private Sigstore ━━━${NC}"
            install_kubewarden
            configure_policy_server
            deploy_and_verify_policy
            evaluate_policy_in_cluster
        fi
    else
        echo -e "${YELLOW}⏭  Stage 3 skipped (--skip-kubewarden)${NC}"
    fi

    print_summary
}

main "$@"
