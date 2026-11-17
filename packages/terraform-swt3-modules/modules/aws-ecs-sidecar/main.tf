# SWT3 Infrastructure Witness -- AWS ECS Sidecar Module
#
# Outputs a container definition JSON fragment that can be merged into
# existing ECS task definitions. The sidecar runs swt3-infra-witness
# in server mode, accepting cloud audit events via HTTP on localhost.
#
# Usage in your task definition:
#   container_definitions = jsonencode(concat(
#     [your_primary_container],
#     [module.swt3_sidecar.container_definition],
#   ))
#
# The primary container sends events to http://localhost:8080/ and the
# sidecar witnesses them through the SWT3 protocol.

locals {
  container_name = "${var.name_prefix}-infra-witness"
  # Use digest-pinned image if provided (red team #1)
  image = var.container_image_digest != "" ? "${split(":", var.container_image)[0]}@${var.container_image_digest}" : var.container_image

  region = var.aws_region != "" ? var.aws_region : data.aws_region.current.name

  secrets = compact([
    jsonencode({
      name      = "SWT3_API_KEY"
      valueFrom = var.swt3_api_key_secret_arn
    }),
    var.signing_key_secret_arn != "" ? jsonencode({
      name      = "SWT3_SIGNING_KEY"
      valueFrom = var.signing_key_secret_arn
    }) : "",
  ])
}

data "aws_region" "current" {}

# --- IAM Policy for Secrets Manager access ---
# Attach this to your ECS task execution role.

data "aws_iam_policy_document" "secrets_access" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = compact([
      var.swt3_api_key_secret_arn,
      var.signing_key_secret_arn,
    ])
  }
}

resource "aws_iam_policy" "sidecar_secrets" {
  name   = "${var.name_prefix}-sidecar-secrets"
  policy = data.aws_iam_policy_document.secrets_access.json
  tags   = var.tags
}
