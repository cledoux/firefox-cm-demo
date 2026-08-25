output "gcp_wif_provider" {
  description = "The full resource identifier for the Workload Identity Provider to set as GitHub Secret GCP_WIF_PROVIDER."
  value       = google_iam_workload_identity_pool_provider.provider.name
}

output "gcp_service_account" {
  description = "The email address of the dedicated Service Account to set as GitHub Secret GCP_SERVICE_ACCOUNT."
  value       = google_service_account.runner.email
}

output "workload_identity_pool_name" {
  description = "The full resource name of the Workload Identity Pool."
  value       = google_iam_workload_identity_pool.pool.name
}

output "github_secrets_instructions" {
  description = "Formatted instructions for configuring GitHub repository secrets."
  value       = <<-EOT
    ================================================================================
    ✓ Workload Identity Federation configuration complete via Terraform!
    ================================================================================

    Add the following secrets to your GitHub repository (${var.github_repo}):

      GCP_WIF_PROVIDER: ${google_iam_workload_identity_pool_provider.provider.name}
      GCP_SERVICE_ACCOUNT: ${google_service_account.runner.email}

    ================================================================================
  EOT
}
