# SWT3 Infrastructure Witness -- GCP Cloud Function Module
#
# Deploys a Cloud Function (gen2) that reads GCP Audit Log events via
# Pub/Sub and witnesses them through the SWT3 protocol.
#
# Red team mitigations:
#   #1  Container image digest validation
#   #3  Secret Manager resource name only, raw key rejected
#   #5  Deployment fingerprint output
#   #10 Exact version pins

variable "swt3_api_key_secret_id" {
  description = "GCP Secret Manager secret resource name for the SWT3 API key. Format: projects/<project>/secrets/<name>/versions/<version>. NEVER pass a raw key."
  type        = string

  validation {
    condition     = can(regex("^projects/", var.swt3_api_key_secret_id))
    error_message = "Must be a GCP Secret Manager resource name (projects/<project>/secrets/<name>/versions/<version>). Never pass a raw API key."
  }
}

variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "GCP region for the Cloud Function and Pub/Sub resources."
  type        = string
  default     = "us-central1"
}

variable "container_image" {
  description = "Container image for swt3-infra-witness. Always pin to exact tag."
  type        = string
  default     = "ghcr.io/tenova-labs/swt3-infra-witness:8.1.0"
}

variable "container_image_digest" {
  description = "SHA-256 image digest for integrity verification. Leave empty to skip."
  type        = string
  default     = ""
}

variable "clearing_level" {
  description = "SWT3 clearing level: 0=analytics, 1=standard, 2=sensitive, 3=classified."
  type        = number
  default     = 1

  validation {
    condition     = var.clearing_level >= 0 && var.clearing_level <= 3
    error_message = "Clearing level must be 0-3."
  }
}

variable "agent_id" {
  description = "Agent identity for this Cloud Function deployment."
  type        = string
  default     = "swt3-gcp-cloud-function"
}

variable "signing_key_secret_id" {
  description = "Secret Manager resource name for optional HMAC-SHA256 signing key."
  type        = string
  default     = ""

  validation {
    condition     = var.signing_key_secret_id == "" || can(regex("^projects/", var.signing_key_secret_id))
    error_message = "Must be empty or a GCP Secret Manager resource name."
  }
}

variable "endpoint" {
  description = "SWT3 witness endpoint URL."
  type        = string
  default     = "https://sovereign.tenova.io/api/v1/witness/ocsf"
}

variable "name_prefix" {
  description = "Prefix for all created resources."
  type        = string
  default     = "swt3"
}

variable "audit_log_filter" {
  description = "Cloud Logging filter for the Log Router sink. Default captures all admin activity."
  type        = string
  default     = "logName:\"logs/cloudaudit.googleapis.com%2Factivity\" OR logName:\"logs/cloudaudit.googleapis.com%2Fsystem_event\""
}

variable "max_instances" {
  description = "Maximum Cloud Function instances for concurrency control."
  type        = number
  default     = 10
}

variable "labels" {
  description = "Labels to apply to all created resources."
  type        = map(string)
  default     = {}
}
