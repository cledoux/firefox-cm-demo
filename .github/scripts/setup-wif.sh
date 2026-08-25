#!/usr/bin/env bash
# github-actions/scripts/setup-wif.sh - Google Cloud Workload Identity Federation Helper Script
# Governing: REQ-0002.3, REQ-0008.7, REQ-0008.8, REQ-0008.9, REQ-0008.10, REQ-0008.11, REQ-0008.12, REQ-0008.13
set -euo pipefail

# Default values
POOL_NAME="${POOL_NAME:-codemender-pool}"
PROVIDER_NAME="${PROVIDER_NAME:-codemender-provider}"
SA_NAME="${SA_NAME:-codemender-runner}"
PROJECT_ID="${PROJECT_ID:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
PROJECT_NUM="${PROJECT_NUM:-}"
DRY_RUN="${DRY_RUN:-false}"

show_help() {
  cat << 'EOF'
Usage: ./github-actions/scripts/setup-wif.sh [OPTIONS] [PROJECT_ID GITHUB_REPO [POOL_NAME] [PROVIDER_NAME] [SA_NAME]]

Provisions Google Cloud Workload Identity Federation (WIF) resources and IAM bindings
for keyless GitHub Actions CI/CD workflows.

Options:
  -p, --project, --project=<ID>       Google Cloud Project ID (Required)
  -r, --repo, --github-repo=<OWNER/REPO>
                                      GitHub repository in owner/repo format (Required)
      --pool, --pool-name=<NAME>      Workload Identity Pool name (Default: codemender-pool)
      --provider, --provider-name=<NAME>
                                      Workload Identity Provider name (Default: codemender-provider)
  -s, --sa, --sa-name, --service-account=<NAME>
                                      Service Account name (Default: codemender-runner)
  -d, --dry-run                       Print gcloud commands without executing them
  -h, --help                          Show this help message and exit

Environment Variables:
  PROJECT_ID                          Google Cloud Project ID
  GITHUB_REPO                         GitHub repository (owner/repo)
  POOL_NAME                           Workload Identity Pool name
  PROVIDER_NAME                       Workload Identity Provider name
  SA_NAME                             Service Account name
  PROJECT_NUM                         Google Cloud Project Number (auto-discovered if omitted)
  DRY_RUN                             Set to 'true' or '1' to enable dry-run mode

Examples:
  ./github-actions/scripts/setup-wif.sh -p my-gcp-project -r my-org/my-repo
  ./github-actions/scripts/setup-wif.sh --project=my-gcp-project --repo=my-org/my-repo --dry-run
  ./github-actions/scripts/setup-wif.sh my-gcp-project my-org/my-repo custom-pool custom-provider custom-sa
EOF
}

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    -d|--dry-run)
      DRY_RUN="true"
      shift
      ;;
    --dry-run=*)
      DRY_RUN="${1#*=}"
      shift
      ;;
    -p|--project)
      PROJECT_ID="$2"
      shift 2
      ;;
    --project=*)
      PROJECT_ID="${1#*=}"
      shift
      ;;
    -r|--repo|--github-repo)
      GITHUB_REPO="$2"
      shift 2
      ;;
    --repo=*|--github-repo=*)
      GITHUB_REPO="${1#*=}"
      shift
      ;;
    --pool|--pool-name)
      POOL_NAME="$2"
      shift 2
      ;;
    --pool=*|--pool-name=*)
      POOL_NAME="${1#*=}"
      shift
      ;;
    --provider|--provider-name)
      PROVIDER_NAME="$2"
      shift 2
      ;;
    --provider=*|--provider-name=*)
      PROVIDER_NAME="${1#*=}"
      shift
      ;;
    -s|--sa|--sa-name|--service-account)
      SA_NAME="$2"
      shift 2
      ;;
    --sa=*|--sa-name=*|--service-account=*)
      SA_NAME="${1#*=}"
      shift
      ;;
    -*)
      echo "Error: Unknown option: $1" >&2
      echo "Run with --help for usage details." >&2
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

# Map positional arguments if provided
if [ ${#POSITIONAL_ARGS[@]} -ge 1 ] && [ -z "${PROJECT_ID}" ]; then
  PROJECT_ID="${POSITIONAL_ARGS[0]}"
fi
if [ ${#POSITIONAL_ARGS[@]} -ge 2 ] && [ -z "${GITHUB_REPO}" ]; then
  GITHUB_REPO="${POSITIONAL_ARGS[1]}"
fi
if [ ${#POSITIONAL_ARGS[@]} -ge 3 ]; then
  POOL_NAME="${POSITIONAL_ARGS[2]}"
fi
if [ ${#POSITIONAL_ARGS[@]} -ge 4 ]; then
  PROVIDER_NAME="${POSITIONAL_ARGS[3]}"
fi
if [ ${#POSITIONAL_ARGS[@]} -ge 5 ]; then
  SA_NAME="${POSITIONAL_ARGS[4]}"
fi

# Validation: Mandatory parameters
if [ -z "${PROJECT_ID}" ]; then
  echo "Error: Missing required parameter: PROJECT_ID (--project or -p)" >&2
  exit 1
fi

if [ -z "${GITHUB_REPO}" ]; then
  echo "Error: Missing required parameter: GITHUB_REPO (--repo or -r)" >&2
  exit 1
fi

# Resolve project number
if [ -z "${PROJECT_NUM}" ]; then
  if [ "${DRY_RUN}" = "true" ] || [ "${DRY_RUN}" = "1" ]; then
    PROJECT_NUM="123456789012"
  else
    PROJECT_NUM=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')
  fi
fi

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
WIF_PROVIDER_RESOURCE="projects/${PROJECT_NUM}/locations/global/workloadIdentityPools/${POOL_NAME}/providers/${PROVIDER_NAME}"
PRINCIPAL_SET="principalSet://iam.googleapis.com/projects/${PROJECT_NUM}/locations/global/workloadIdentityPools/${POOL_NAME}/attribute.repository/${GITHUB_REPO}"

run_step() {
  local description="$1"
  local cmd="$2"

  echo "==> ${description}"
  if [ "${DRY_RUN}" = "true" ] || [ "${DRY_RUN}" = "1" ]; then
    echo "[DRY-RUN] ${cmd}"
  else
    eval "${cmd}"
  fi
}

echo "Configuring Workload Identity Federation for ${GITHUB_REPO} on project ${PROJECT_ID}..."

# 1. Create Workload Identity Pool [REQ-0008.7]
run_step "Creating Workload Identity Pool (${POOL_NAME})" \
  "gcloud iam workload-identity-pools create ${POOL_NAME} --project=\"${PROJECT_ID}\" --location=\"global\" --display-name=\"CodeMender Identity Pool\""

# 2. Create OIDC Provider [REQ-0008.8]
run_step "Creating OIDC Workload Identity Provider (${PROVIDER_NAME})" \
  "gcloud iam workload-identity-pools providers create-oidc ${PROVIDER_NAME} --project=\"${PROJECT_ID}\" --location=\"global\" --workload-identity-pool=\"${POOL_NAME}\" --issuer-uri=\"https://token.actions.githubusercontent.com\" --attribute-mapping=\"google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner\" --attribute-condition=\"assertion.repository == '${GITHUB_REPO}'\" --display-name=\"CodeMender GitHub Provider\""

# 3. Create Service Account [REQ-0008.9]
run_step "Creating Service Account (${SA_NAME})" \
  "gcloud iam service-accounts create ${SA_NAME} --project=\"${PROJECT_ID}\" --display-name=\"CodeMender Runner\""

# 4. Bind aiplatform.user to Service Account [REQ-0008.10]
run_step "Binding roles/aiplatform.user on project to Service Account" \
  "gcloud projects add-iam-policy-binding ${PROJECT_ID} --member=\"serviceAccount:${SA_EMAIL}\" --role=\"roles/aiplatform.user\""

# 5. Bind workloadIdentityUser on Service Account to GitHub Repo PrincipalSet [REQ-0008.11]
run_step "Binding roles/iam.workloadIdentityUser to GitHub Actions PrincipalSet" \
  "gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --project=\"${PROJECT_ID}\" --role=\"roles/iam.workloadIdentityUser\" --member=\"${PRINCIPAL_SET}\""

# 6. Output GitHub Secrets instructions [REQ-0008.12]
echo ""
echo "================================================================================"
echo "✓ Workload Identity Federation configuration complete!"
echo "================================================================================"
echo ""
echo "Add the following secrets to your GitHub repository (${GITHUB_REPO}):"
echo ""
echo "  GCP_WIF_PROVIDER: ${WIF_PROVIDER_RESOURCE}"
echo "  GCP_SERVICE_ACCOUNT: ${SA_EMAIL}"
echo ""
echo "================================================================================"
