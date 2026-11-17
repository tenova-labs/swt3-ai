# SWT3 Infrastructure Witness -- AWS Lambda CloudTrail Module
#
# Deploys a Lambda function that reads CloudTrail events from S3 via SQS
# and witnesses them through the SWT3 protocol.
#
# Red team mitigations:
#   #1  Binary integrity:    binary_sha256 required, verified at deploy
#   #3  API key in TF state: Secrets Manager ARN only, raw key rejected
#   #5  Deployment fingerprint: output for portal registration
#   #10 Unpinned versions:   Exact version pins in all defaults

variable "swt3_api_key_secret_arn" {
  description = "AWS Secrets Manager ARN containing the SWT3 API key (axm_*). NEVER pass a raw key."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:", var.swt3_api_key_secret_arn))
    error_message = "Must be an AWS Secrets Manager ARN (arn:aws:secretsmanager:...). Never pass a raw API key -- store it in Secrets Manager first."
  }
}

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket receiving CloudTrail logs."
  type        = string
}

variable "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail S3 bucket."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:s3:::", var.cloudtrail_bucket_arn))
    error_message = "Must be an S3 bucket ARN (arn:aws:s3:::...)."
  }
}

variable "binary_version" {
  description = "Version of the swt3-infra-witness binary. Always pin to an exact version."
  type        = string
  default     = "8.1.0"
}

variable "binary_sha256" {
  description = "SHA-256 checksum of the binary. Verified at deploy time. Get from checksums.json in the release."
  type        = string

  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.binary_sha256))
    error_message = "Must be a 64-character hex SHA-256 hash."
  }
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
  description = "Agent identity for this Lambda deployment."
  type        = string
  default     = "swt3-lambda-cloudtrail"
}

variable "signing_key_secret_arn" {
  description = "Secrets Manager ARN for optional HMAC-SHA256 signing key. Leave empty to skip signing."
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
  description = "Prefix for all created resources."
  type        = string
  default     = "swt3"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds."
  type        = number
  default     = 60
}

variable "lambda_memory" {
  description = "Lambda function memory in MB."
  type        = number
  default     = 128
}

variable "reserved_concurrent_executions" {
  description = "Maximum concurrent Lambda executions. Prevents burst overload on SWT3 endpoint. Set to -1 for unreserved."
  type        = number
  default     = 10
}

variable "architectures" {
  description = "Lambda CPU architecture. Use arm64 for Graviton (lower cost)."
  type        = list(string)
  default     = ["arm64"]

  validation {
    condition     = length(var.architectures) == 1 && contains(["arm64", "x86_64"], var.architectures[0])
    error_message = "Must be [\"arm64\"] or [\"x86_64\"]."
  }
}

variable "s3_prefix" {
  description = "S3 key prefix filter for CloudTrail logs. Empty = all objects."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to all created resources."
  type        = map(string)
  default     = {}
}

# --- Alarm variables ---

variable "enable_alarms" {
  description = "Create CloudWatch alarms for Lambda errors, DLQ depth, duration, and throttles."
  type        = bool
  default     = false
}

variable "alarm_sns_topic_arn" {
  description = "Existing SNS topic ARN for alarm notifications. Leave empty to create a new topic."
  type        = string
  default     = ""
}

variable "alarm_email" {
  description = "Email address for alarm notifications. Only used when creating a new SNS topic (alarm_sns_topic_arn is empty)."
  type        = string
  default     = ""
}
