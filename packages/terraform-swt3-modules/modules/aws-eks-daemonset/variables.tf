# SWT3 Infrastructure Witness -- AWS EKS DaemonSet Module
#
# Wraps the official swt3-witness Helm chart as a Terraform-managed release.
# DaemonSet runs on every node, discovers NVIDIA/AMD/TPU/Trainium/Gaudi
# hardware, and witnesses attestation anchors via the SWT3 protocol.
#
# Red team mitigations:
#   #3  Secrets Manager ARN only, raw key rejected
#   #5  Deployment fingerprint output
#   #10 Exact chart version pin

variable "swt3_api_key_secret_arn" {
  description = "AWS Secrets Manager ARN containing the SWT3 API key. NEVER pass a raw key."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:", var.swt3_api_key_secret_arn))
    error_message = "Must be an AWS Secrets Manager ARN. Never pass a raw API key."
  }
}

variable "tenant_id" {
  description = "SWT3 tenant identifier."
  type        = string
}

variable "chart_version" {
  description = "Helm chart version. Always pin to an exact version."
  type        = string
  default     = "8.1.0"
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
  description = "Agent identity prefix. Pod hostname is appended automatically."
  type        = string
  default     = ""
}

variable "signing_key_secret_arn" {
  description = "Secrets Manager ARN for optional HMAC-SHA256 signing key."
  type        = string
  default     = ""

  validation {
    condition     = var.signing_key_secret_arn == "" || can(regex("^arn:aws:secretsmanager:", var.signing_key_secret_arn))
    error_message = "Must be empty or an AWS Secrets Manager ARN."
  }
}

variable "endpoint" {
  description = "SWT3 witness endpoint URL."
  type        = string
  default     = "https://sovereign.tenova.io"
}

variable "attestation_interval" {
  description = "Seconds between hardware attestation cycles."
  type        = number
  default     = 3600
}

variable "name_prefix" {
  description = "Prefix for the Helm release name."
  type        = string
  default     = "swt3"
}

variable "namespace" {
  description = "Kubernetes namespace for the DaemonSet."
  type        = string
  default     = "swt3-system"
}

variable "create_namespace" {
  description = "Create the namespace if it does not exist."
  type        = bool
  default     = true
}

variable "runtime_class_name" {
  description = "Kubernetes RuntimeClassName. Set to 'nvidia' for full GPU discovery."
  type        = string
  default     = ""
}

variable "node_selector" {
  description = "Node selector for DaemonSet scheduling."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Tolerations for DaemonSet scheduling (e.g., GPU taints)."
  type = list(object({
    key      = optional(string)
    operator = optional(string)
    value    = optional(string)
    effect   = optional(string)
  }))
  default = []
}

variable "tags" {
  description = "Tags for AWS resources."
  type        = map(string)
  default     = {}
}
