# Data source for resolving Google Cloud project number
data "google_project" "project" {
  project_id = var.project_id
}

# 1. Create Workload Identity Pool [REQ-0008.7]
resource "google_iam_workload_identity_pool" "pool" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = var.pool_display_name
  description               = "Workload Identity Pool for CodeMender GitHub Actions CI/CD workflows"
  disabled                  = false
}

# 2. Create OIDC Provider for GitHub Actions [REQ-0008.8]
resource "google_iam_workload_identity_pool_provider" "provider" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = var.provider_display_name
  description                        = "OIDC Provider for GitHub Actions token.actions.githubusercontent.com"
  disabled                           = false

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }

  attribute_condition = "assertion.repository == \"${var.github_repo}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# 3. Create Dedicated Service Account for CodeMender Runner [REQ-0008.9]
resource "google_service_account" "runner" {
  project      = var.project_id
  account_id   = var.sa_name
  display_name = var.sa_display_name
  description  = "Service account used by CodeMender GitHub Actions CI/CD runner for Vertex AI access"
}

# 4. Bind roles/aiplatform.user on Project to Service Account [REQ-0008.10]
resource "google_project_iam_member" "aiplatform_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.runner.email}"
}

# 5. Bind roles/iam.workloadIdentityUser to GitHub Repository PrincipalSet [REQ-0008.11]
resource "google_service_account_iam_member" "wif_user" {
  service_account_id = google_service_account.runner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.pool.name}/attribute.repository/${var.github_repo}"
}
