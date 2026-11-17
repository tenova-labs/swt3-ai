# Outputs for the SWT3 ECS Sidecar module.

output "container_definition" {
  description = "Container definition object to merge into your ECS task definition. Use: container_definitions = jsonencode(concat([your_app], [module.swt3_sidecar.container_definition]))"
  value = {
    name      = local.container_name
    image     = local.image
    essential = false
    cpu       = var.cpu
    memory    = var.memory

    command = ["--mode", "server", "--port", tostring(var.sidecar_port), "--format", "auto"]

    portMappings = [{
      containerPort = var.sidecar_port
      protocol      = "tcp"
    }]

    environment = [
      { name = "SWT3_ENDPOINT", value = var.endpoint },
      { name = "SWT3_CLEARING_LEVEL", value = tostring(var.clearing_level) },
      { name = "SWT3_AGENT_ID", value = var.agent_id },
    ]

    secrets = [
      { name = "SWT3_API_KEY", valueFrom = var.swt3_api_key_secret_arn },
    ]

    healthCheck = {
      command     = ["CMD-SHELL", "wget -q -O /dev/null http://localhost:${var.sidecar_port}/healthz || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 10
    }

    logConfiguration = var.log_group_name != "" ? {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = var.log_group_name
        "awslogs-region"        = local.region
        "awslogs-stream-prefix" = local.container_name
      }
    } : null
  }
}

output "secrets_policy_arn" {
  description = "IAM policy ARN granting Secrets Manager access. Attach to your ECS task execution role."
  value       = aws_iam_policy.sidecar_secrets.arn
}

output "sidecar_url" {
  description = "URL for the primary container to POST events to the sidecar."
  value       = "http://localhost:${var.sidecar_port}/"
}

# Red team #5: Deployment fingerprint
output "deployment_fingerprint" {
  description = "SHA-256 deployment fingerprint for portal verification."
  value = sha256(jsonencode({
    module         = "aws-ecs-sidecar"
    container_image = var.container_image
    image_digest   = var.container_image_digest
    agent_id       = var.agent_id
    clearing_level = var.clearing_level
    endpoint       = var.endpoint
    region         = local.region
  }))
}

output "post_deploy_verify" {
  description = "Run this from inside the ECS task to verify the sidecar is healthy."
  value       = "curl -s http://localhost:${var.sidecar_port}/healthz | jq ."
}
