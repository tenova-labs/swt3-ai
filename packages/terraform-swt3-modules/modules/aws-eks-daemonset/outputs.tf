# Outputs for the SWT3 EKS DaemonSet module.

output "release_name" {
  description = "Helm release name."
  value       = helm_release.swt3_witness.name
}

output "release_namespace" {
  description = "Kubernetes namespace of the DaemonSet."
  value       = helm_release.swt3_witness.namespace
}

output "chart_version" {
  description = "Deployed Helm chart version."
  value       = helm_release.swt3_witness.version
}

output "release_status" {
  description = "Helm release status."
  value       = helm_release.swt3_witness.status
}

# Red team #5: Deployment fingerprint
output "deployment_fingerprint" {
  description = "SHA-256 deployment fingerprint for portal verification."
  value = sha256(jsonencode({
    module        = "aws-eks-daemonset"
    chart_version = var.chart_version
    tenant_id     = var.tenant_id
    agent_id      = var.agent_id
    clearing_level = var.clearing_level
    endpoint      = var.endpoint
    namespace     = var.namespace
    region        = data.aws_region.current.name
  }))
}

output "post_deploy_verify" {
  description = "Run this to verify the DaemonSet is running and witnessing."
  value       = "kubectl logs -l app.kubernetes.io/name=swt3-witness -n ${var.namespace} --since=5m --tail=20"
}
