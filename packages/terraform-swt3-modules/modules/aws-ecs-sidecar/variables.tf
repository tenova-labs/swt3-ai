# SWT3 Infrastructure Witness -- AWS ECS Sidecar Module
#
# Outputs a container definition JSON fragment to inject into existing
# ECS task definitions. The sidecar runs swt3-infra-witness in server
# mode, receiving events from the primary container via localhost.
#
# Red team mitigations:
#   #1  Container image digest validation
#   #3  Secrets Manager ARN only, raw key rejected
#   #5  Deployment fingerprint output
#   #10 Exact version pins

variable "swt3_api_key_secret_arn" {
  description = "AWS Secrets Manager ARN containing the SWT3 API key. NEVER pass a raw key."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:", var.swt3_api_key_secret_arn))
    error_message = "Must be an AWS Secrets Manager ARN. Never pass a raw API key."
  }
}

variable "container_image" {
  description = "Container image for swt3-infra-witness. Always pin to exact tag."
  type        = string
  default     = "ghcr.io/tenova-labs/swt3-infra-witness:8.1.0"
}

variable "container_image_digest" {
  description = "SHA-256 image digest for integrity verification. Get from 'docker inspect --format={{.RepoDigests}}'. Leave empty to skip digest pinning."
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
  description = "Agent identity for this ECS sidecar."
  type        = string
  default     = "swt3-ecs-sidecar"
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
  default     = "https://sovereign.tenova.io/api/v1/witness/ocsf"
}

variable "name_prefix" {
  description = "Prefix for the sidecar container name."
  type        = string
  default     = "swt3"
}

variable "sidecar_port" {
  description = "Port the sidecar listens on for webhook events from the primary container."
  type        = number
  default     = 8080
}

variable "cpu" {
  description = "CPU units for the sidecar container (1024 = 1 vCPU)."
  type        = number
  default     = 64
}

variable "memory" {
  description = "Memory in MB for the sidecar container."
  type        = number
  default     = 64
}

variable "log_group_name" {
  description = "CloudWatch log group for sidecar logs."
  type        = string
  default     = ""
}

variable "aws_region" {
  description = "AWS region for CloudWatch log configuration."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags for created resources."
  type        = map(string)
  default     = {}
}
