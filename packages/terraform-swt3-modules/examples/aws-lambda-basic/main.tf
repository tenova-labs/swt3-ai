# SWT3 Infrastructure Witness -- Minimal AWS Example
#
# Deploys a Lambda that automatically witnesses all CloudTrail events.
#
# Prerequisites:
#   1. Store your SWT3 API key in Secrets Manager:
#      aws secretsmanager create-secret --name swt3/api-key --secret-string "axm_live_YOUR_KEY"
#
#   2. Have a CloudTrail trail writing to an S3 bucket.
#
# Usage:
#   terraform init
#   terraform plan
#   terraform apply
#
# Source: https://github.com/tenova-labs/terraform-swt3-modules

provider "aws" {
  region = "us-east-1"
}

# Reference your existing CloudTrail bucket
data "aws_s3_bucket" "cloudtrail" {
  bucket = "my-org-cloudtrail-logs"
}

# Reference your SWT3 API key in Secrets Manager
data "aws_secretsmanager_secret" "swt3_api_key" {
  name = "swt3/api-key"
}

module "swt3_witness" {
  source = "../../modules/aws-lambda-cloudtrail"
  # When published to registry, use:
  # source  = "tenova-labs/swt3-modules/aws//modules/aws-lambda-cloudtrail"
  # version = "1.0.0"  # Always pin exact version (red team #10)

  swt3_api_key_secret_arn = data.aws_secretsmanager_secret.swt3_api_key.arn
  cloudtrail_bucket_name  = data.aws_s3_bucket.cloudtrail.id
  cloudtrail_bucket_arn   = data.aws_s3_bucket.cloudtrail.arn

  # Get from checksums.json in the release (red team #1)
  binary_sha256 = "REPLACE_WITH_SHA256_FROM_CHECKSUMS_JSON"

  # Optional overrides
  clearing_level = 1
  agent_id       = "prod-cloudtrail-witness"
  architectures  = ["arm64"]  # Graviton = lower cost

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Purpose     = "swt3-infrastructure-witness"
  }
}

output "deployment_fingerprint" {
  description = "Register this fingerprint in the SWT3 portal for Infrastructure Verified badge."
  value       = module.swt3_witness.deployment_fingerprint
}

output "lambda_function_name" {
  value = module.swt3_witness.lambda_function_name
}

output "post_deploy_verify" {
  description = "Run this after terraform apply to confirm the witness is processing events."
  value       = module.swt3_witness.post_deploy_verify
}
