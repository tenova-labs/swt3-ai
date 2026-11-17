# SWT3 Infrastructure Witness -- AWS EKS DaemonSet Module
#
# Wraps the official swt3-witness Helm chart. Deploys a DaemonSet that
# discovers hardware (NVIDIA, AMD, TPU, Trainium, Gaudi) on every node
# and witnesses attestation anchors via the SWT3 protocol.
#
# Helm chart source: oci://ghcr.io/tenova-labs/charts/swt3-witness
# Chart docs: https://sovereign.tenova.io/docs/

data "aws_region" "current" {}

# Fetch the API key from Secrets Manager at plan time.
# The value is passed to Helm via set_sensitive (never in plan output).
data "aws_secretsmanager_secret_version" "api_key" {
  secret_id = var.swt3_api_key_secret_arn
}

# Optionally fetch signing key
data "aws_secretsmanager_secret_version" "signing_key" {
  count     = var.signing_key_secret_arn != "" ? 1 : 0
  secret_id = var.signing_key_secret_arn
}

locals {
  signing_key = var.signing_key_secret_arn != "" ? data.aws_secretsmanager_secret_version.signing_key[0].secret_string : ""
}

resource "helm_release" "swt3_witness" {
  name             = "${var.name_prefix}-witness"
  repository       = "oci://ghcr.io/tenova-labs/charts"
  chart            = "swt3-witness"
  version          = var.chart_version  # Red team #10: exact pin
  namespace        = var.namespace
  create_namespace = var.create_namespace
  atomic           = true
  timeout          = 300

  # Mode: cloud (flush to SWT3 endpoint)
  set {
    name  = "config.mode"
    value = "cloud"
  }

  set {
    name  = "config.interval"
    value = tostring(var.attestation_interval)
  }

  set {
    name  = "config.clearingLevel"
    value = tostring(var.clearing_level)
  }

  set {
    name  = "config.agentId"
    value = var.agent_id
  }

  # Cloud credentials -- set_sensitive keeps values out of plan output
  set_sensitive {
    name  = "cloud.apiKey"
    value = data.aws_secretsmanager_secret_version.api_key.secret_string
  }

  set {
    name  = "cloud.tenantId"
    value = var.tenant_id
  }

  set {
    name  = "cloud.endpoint"
    value = var.endpoint
  }

  set_sensitive {
    name  = "cloud.signingKey"
    value = local.signing_key
  }

  # Runtime class for GPU discovery
  dynamic "set" {
    for_each = var.runtime_class_name != "" ? [var.runtime_class_name] : []
    content {
      name  = "runtimeClassName"
      value = set.value
    }
  }

  # Node selector
  dynamic "set" {
    for_each = var.node_selector
    content {
      name  = "nodeSelector.${set.key}"
      value = set.value
    }
  }
}
