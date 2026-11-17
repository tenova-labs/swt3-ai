# IAM role and policies for the SWT3 witness Lambda function.
# Follows least-privilege: only the permissions needed to read CloudTrail
# events from S3 via SQS and fetch secrets from Secrets Manager.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "witness_lambda" {
  name               = "${var.name_prefix}-witness-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.tags
}

# SQS: receive and delete messages
data "aws_iam_policy_document" "sqs_access" {
  statement {
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.witness_queue.arn]
  }
}

resource "aws_iam_role_policy" "sqs_access" {
  name   = "${var.name_prefix}-sqs-access"
  role   = aws_iam_role.witness_lambda.id
  policy = data.aws_iam_policy_document.sqs_access.json
}

# S3: read CloudTrail log objects
data "aws_iam_policy_document" "s3_access" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${var.cloudtrail_bucket_arn}/*"]
  }
}

resource "aws_iam_role_policy" "s3_access" {
  name   = "${var.name_prefix}-s3-access"
  role   = aws_iam_role.witness_lambda.id
  policy = data.aws_iam_policy_document.s3_access.json
}

# Secrets Manager: read API key (and optionally signing key)
data "aws_iam_policy_document" "secrets_access" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = compact([
      var.swt3_api_key_secret_arn,
      var.signing_key_secret_arn,
    ])
  }
}

resource "aws_iam_role_policy" "secrets_access" {
  name   = "${var.name_prefix}-secrets-access"
  role   = aws_iam_role.witness_lambda.id
  policy = data.aws_iam_policy_document.secrets_access.json
}

# CloudWatch Logs: write Lambda execution logs
data "aws_iam_policy_document" "logs_access" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "logs_access" {
  name   = "${var.name_prefix}-logs-access"
  role   = aws_iam_role.witness_lambda.id
  policy = data.aws_iam_policy_document.logs_access.json
}
