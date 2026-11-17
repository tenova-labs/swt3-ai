# SWT3 Infrastructure Witness -- Azure Function Module
#
# Deploys an Azure Function that reads Activity Log events via Event Grid
# and witnesses them through the SWT3 protocol.
#
# Red team mitigations:
#   #1  Container image digest validation
#   #3  Key Vault secret URI only, raw key rejected
#   #5  Deployment fingerprint output
#   #10 Exact version pins

variable "swt3_api_key_vault_id" {
  description = "Azure Key Vault secret URI for the SWT3 API key. Format: https://<vault>.vault.azure.net/secrets/<name>. NEVER pass a raw key."
  type        = string

  validation {
    condition     = can(regex("^https://.*\\.vault\\.azure\\.net/secrets/", var.swt3_api_key_vault_id))
    error_message = "Must be an Azure Key Vault secret URI (https://<vault>.vault.azure.net/secrets/<name>). Never pass a raw API key."
  }
}

variable "resource_group_name" {
  description = "Azure Resource Group for all created resources."
  type        = string
}

variable "location" {
  description = "Azure region (e.g., eastus, westeurope)."
  type        = string
}

variable "container_image" {
  description = "Container image for swt3-infra-witness. Always pin to exact tag."
  type        = string
  default     = "ghcr.io/tenova-labs/swt3-infra-witness:8.1.0"
}

variable "container_image_digest" {
  description = "SHA-256 image digest for integrity verification. Leave empty to skip digest pinning."
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
  description = "Agent identity for this Azure Function deployment."
  type        = string
  default     = "swt3-azure-function"
}

variable "signing_key_vault_id" {
  description = "Key Vault secret URI for optional HMAC-SHA256 signing key."
  type        = string
  default     = ""

  validation {
    condition     = var.signing_key_vault_id == "" || can(regex("^https://.*\\.vault\\.azure\\.net/secrets/", var.signing_key_vault_id))
    error_message = "Must be empty or an Azure Key Vault secret URI."
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

variable "subscription_id" {
  description = "Azure Subscription ID to monitor via Activity Log. Defaults to current subscription."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to all created resources."
  type        = map(string)
  default     = {}
}
