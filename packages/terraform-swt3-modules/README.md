# SWT3 Infrastructure Witness -- Terraform Modules

Terraform/OpenTofu modules for deploying cryptographic infrastructure witnesses across AWS, Azure, and GCP. Each module reads cloud audit logs, extracts canonical fields, computes deterministic hashes, and witnesses them via the SWT3 protocol. Raw audit data never leaves your cloud account.

## Modules

| Module | Cloud | Pattern | Description |
|--------|-------|---------|-------------|
| [aws-lambda-cloudtrail](modules/aws-lambda-cloudtrail) | AWS | S3 -> SQS -> Lambda | Witnesses CloudTrail events via Lambda |
| [aws-ecs-sidecar](modules/aws-ecs-sidecar) | AWS | ECS task sidecar | Container definition for existing ECS tasks |
| [aws-eks-daemonset](modules/aws-eks-daemonset) | AWS | Helm DaemonSet | Hardware attestation on every EKS node |
| [azure-function](modules/azure-function) | Azure | Event Grid -> Function | Witnesses Activity Log events |
| [gcp-cloud-function](modules/gcp-cloud-function) | GCP | Log Router -> Pub/Sub -> Function | Witnesses Cloud Audit Log events |

## Quick Start (AWS Lambda)

```hcl
# 1. Store your API key in Secrets Manager (once)
# aws secretsmanager create-secret --name swt3/api-key --secret-string "axm_live_YOUR_KEY"

module "swt3_witness" {
  source  = "tenova-labs/swt3-modules/aws//modules/aws-lambda-cloudtrail"
  version = "1.0.0"

  swt3_api_key_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:swt3/api-key"
  cloudtrail_bucket_name  = "my-org-cloudtrail-logs"
  cloudtrail_bucket_arn   = "arn:aws:s3:::my-org-cloudtrail-logs"
  binary_sha256           = "REPLACE_WITH_SHA256_FROM_CHECKSUMS_JSON"
}
```

After `terraform apply`, verify it's working:

```bash
# The module outputs a verification command:
terraform output post_deploy_verify
# Run it:
aws logs tail /aws/lambda/swt3-infra-witness --since 5m --format short
```

## Security

All modules enforce cloud-native secret stores. **Raw API keys cannot be passed.**

- **AWS**: Secrets Manager ARN required (regex-validated)
- **Azure**: Key Vault secret URI required (regex-validated)
- **GCP**: Secret Manager resource name required (regex-validated)

Every module outputs a `deployment_fingerprint` (SHA-256 of the deployment config) for portal verification. Container images support digest pinning for supply chain integrity.

## Requirements

- Terraform >= 1.5 (or OpenTofu >= 1.6)
- Cloud provider credentials with permissions to create the resources listed in each module's `iam.tf` or equivalent

## Docs

- Protocol spec: https://swt3.ai/spec
- SDK docs: https://sovereign.tenova.io/docs
- Procedure registry: https://swt3.ai/registry

## Trademarks

Terraform is a trademark of HashiCorp. OpenTofu is a trademark of the Linux Foundation. These modules are not endorsed by or affiliated with HashiCorp or the Linux Foundation.
