# Outputs for the SWT3 Infrastructure Witness Lambda module.

output "lambda_function_arn" {
  description = "ARN of the witness Lambda function."
  value       = aws_lambda_function.witness.arn
}

output "lambda_function_name" {
  description = "Name of the witness Lambda function."
  value       = aws_lambda_function.witness.function_name
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue receiving S3 events."
  value       = aws_sqs_queue.witness_queue.arn
}

output "sqs_dlq_arn" {
  description = "ARN of the dead letter queue for poison messages. Monitor this for processing failures."
  value       = aws_sqs_queue.witness_dlq.arn
}

output "sqs_queue_url" {
  description = "URL of the SQS queue."
  value       = aws_sqs_queue.witness_queue.id
}

output "iam_role_arn" {
  description = "ARN of the Lambda execution IAM role."
  value       = aws_iam_role.witness_lambda.arn
}

output "log_group_name" {
  description = "CloudWatch Log Group for the witness Lambda."
  value       = aws_cloudwatch_log_group.witness.name
}

# Red team #5: Deployment fingerprint for portal registration.
# The portal can verify that witnessed anchors came from a known
# Terraform-managed deployment, not a spoofed source.
output "deployment_fingerprint" {
  description = "SHA-256 deployment fingerprint for portal verification. Include in swt3.yaml or pass as SWT3_DEPLOYMENT_FINGERPRINT."
  value = sha256(jsonencode({
    module         = "aws-lambda-cloudtrail"
    binary_version = var.binary_version
    binary_sha256  = var.binary_sha256
    agent_id       = var.agent_id
    clearing_level = var.clearing_level
    architectures  = var.architectures
    endpoint       = var.endpoint
    region         = data.aws_region.current.name
  }))
}

# Post-deploy verification command. Uses CloudWatch logs (IAM-authenticated),
# not anchor URLs (red team #1: no anchor IDs in Terraform state/CI logs).
output "post_deploy_verify" {
  description = "Run this after deploy to verify the witness is processing CloudTrail events."
  value       = "aws logs tail /aws/lambda/${local.function_name} --since 5m --format short"
}

data "aws_region" "current" {}

# --- Alarm outputs ---

output "alarm_sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications. Empty if alarms are disabled."
  value       = local.alarm_topic_arn
}
