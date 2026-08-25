variable "project_id" {
  description = "The Google Cloud Project ID hosting CodeMender Vertex AI models."
  type        = string
}

variable "github_repo" {
  description = "The target GitHub repository in 'owner/repo' format (e.g. 'cledoux/cm-connect')."
  type        = string
}

variable "pool_id" {
  description = "The ID of the Google Cloud Workload Identity Pool."
  type        = string
  default     = "codemender-pool"
}

variable "pool_display_name" {
  description = "Display name of the Workload Identity Pool (max 32 chars)."
  type        = string
  default     = "CodeMender Identity Pool"
}

variable "provider_id" {
  description = "The ID of the Google Cloud Workload Identity Pool Provider."
  type        = string
  default     = "codemender-provider"
}

variable "provider_display_name" {
  description = "Display name of the Workload Identity Pool Provider (max 32 chars)."
  type        = string
  default     = "CodeMender GitHub Provider"
}

variable "sa_name" {
  description = "The account ID for the dedicated CodeMender GitHub Actions runner Service Account."
  type        = string
  default     = "codemender-runner"
}

variable "sa_display_name" {
  description = "Display name of the CodeMender Service Account."
  type        = string
  default     = "CodeMender Runner"
}
