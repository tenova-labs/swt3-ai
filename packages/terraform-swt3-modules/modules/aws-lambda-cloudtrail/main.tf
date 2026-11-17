# SWT3 Infrastructure Witness -- AWS Lambda CloudTrail Module
#
# Deploys: Lambda + SQS + S3 event notification + IAM (least privilege)
#
# Architecture:
#   S3 (CloudTrail logs) -> SQS -> Lambda (swt3-infra-witness) -> SWT3 API
#
# The Lambda function reads CloudTrail JSON from S3, extracts 6 canonical
# fields, computes deterministic hashes, and witnesses via the SWT3 protocol.
# Raw audit data never leaves your AWS account.
#
# Source: https://github.com/tenova-labs/terraform-swt3-modules

locals {
  function_name = "${var.name_prefix}-infra-witness"
  image_uri     = "ghcr.io/tenova-labs/swt3-infra-witness:${var.binary_version}"

  common_tags = merge(var.tags, {
    "swt3:module"  = "aws-lambda-cloudtrail"
    "swt3:version" = var.binary_version
  })
}

# --- SQS Queue ---
# Receives S3 event notifications when new CloudTrail logs arrive.

resource "aws_sqs_queue" "witness_dlq" {
  name                      = "${var.name_prefix}-witness-dlq"
  message_retention_seconds = 1209600  # 14 days -- time to investigate poison messages
  tags                      = local.common_tags
}

resource "aws_sqs_queue" "witness_queue" {
  name                       = "${var.name_prefix}-witness-events"
  visibility_timeout_seconds = var.lambda_timeout * 6
  message_retention_seconds  = 86400
  tags                       = local.common_tags

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.witness_dlq.arn
    maxReceiveCount     = 3  # After 3 failures, move to DLQ
  })
}

data "aws_iam_policy_document" "sqs_allow_s3" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.witness_queue.arn]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [var.cloudtrail_bucket_arn]
    }
  }
}

resource "aws_sqs_queue_policy" "allow_s3" {
  queue_url = aws_sqs_queue.witness_queue.id
  policy    = data.aws_iam_policy_document.sqs_allow_s3.json
}

# --- S3 Event Notification ---
# Triggers SQS when new CloudTrail log files are written.

resource "aws_s3_bucket_notification" "cloudtrail_to_sqs" {
  bucket = var.cloudtrail_bucket_name

  queue {
    queue_arn     = aws_sqs_queue.witness_queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = var.s3_prefix
    filter_suffix = ".json.gz"
  }

  depends_on = [aws_sqs_queue_policy.allow_s3]
}

# --- Lambda Function ---
# Runs the swt3-infra-witness binary as a container image.
# API key is fetched from Secrets Manager at runtime (red team #3).

resource "aws_lambda_function" "witness" {
  function_name = local.function_name
  role          = aws_iam_role.witness_lambda.arn
  package_type  = "Image"
  image_uri     = local.image_uri
  architectures                  = var.architectures
  timeout                        = var.lambda_timeout
  memory_size                    = var.lambda_memory
  reserved_concurrent_executions = var.reserved_concurrent_executions
  tags                           = local.common_tags

  environment {
    variables = {
      SWT3_ENDPOINT        = var.endpoint
      SWT3_CLEARING_LEVEL  = tostring(var.clearing_level)
      SWT3_AGENT_ID        = var.agent_id
      SWT3_SECRET_ARN      = var.swt3_api_key_secret_arn
      SWT3_SIGN_SECRET_ARN = var.signing_key_secret_arn
      # API key is NOT in env vars. Lambda reads from Secrets Manager at boot.
    }
  }

  image_config {
    command = ["--mode", "cli", "--format", "cloudtrail"]
  }
}

# --- SQS -> Lambda Event Source Mapping ---

resource "aws_lambda_event_source_mapping" "sqs_to_lambda" {
  event_source_arn                   = aws_sqs_queue.witness_queue.arn
  function_name                      = aws_lambda_function.witness.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 30
  enabled                            = true
}

# --- CloudWatch Log Group ---

resource "aws_cloudwatch_log_group" "witness" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
  tags              = local.common_tags
}
