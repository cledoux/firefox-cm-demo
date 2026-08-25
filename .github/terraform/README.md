# Google Cloud Workload Identity Federation (WIF) Terraform Module

This directory provides a declarative, production-grade Terraform configuration
to provision Google Cloud Workload Identity Federation (WIF) resources and IAM
bindings for keyless GitHub Actions CI/CD workflows with CodeMender (`cm`).

## Provisioned Resources

1. **`google_iam_workload_identity_pool`**: Global Workload Identity Pool
   (`codemender-pool`).
1. **`google_iam_workload_identity_pool_provider`**: OIDC Provider linked to
   `https://token.actions.githubusercontent.com` with `google.subject` and
   `attribute.repository` claim mappings.
1. **`google_service_account`**: Dedicated runner service account
   (`codemender-runner`).
1. **`google_project_iam_member`**: Grants `roles/aiplatform.user` on the
   project to the service account.
1. **`google_service_account_iam_member`**: Grants
   `roles/iam.workloadIdentityUser` on the service account restricted strictly
   to
   `principalSet://iam.googleapis.com/<pool-name>/attribute.repository/<github-repo>`.

## Usage

### 1. Configure Variables

Copy `terraform.tfvars.example` to `terraform.tfvars` and edit with your project
details:

```bash
cp terraform.tfvars.example terraform.tfvars
```

```hcl
project_id  = "my-gcp-project"
github_repo = "my-org/my-repo"
```

### 2. Initialize and Apply

```bash
cd github-actions/terraform
terraform init
terraform plan
terraform apply
```

### 3. Copy GitHub Secrets

Terraform displays the outputs upon completion:

```bash
Outputs:

gcp_service_account = "codemender-runner@my-gcp-project.iam.gserviceaccount.com"
gcp_wif_provider = "projects/123456789012/locations/global/workloadIdentityPools/codemender-pool/providers/codemender-provider"
```

Add `GCP_WIF_PROVIDER` and `GCP_SERVICE_ACCOUNT` to your GitHub repository under
**Settings > Secrets and variables > Actions**.
