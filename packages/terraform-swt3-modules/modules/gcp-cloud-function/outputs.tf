# Outputs for the SWT3 GCP Cloud Function module.

output "function_name" {
  description = "Name of the Cloud Function."
  value       = google_cloudfunctions2_function.witness.name
}

output "function_uri" {
  description = "URI of the Cloud Function."
  value       = google_cloudfunctions2_function.witness.service_config[0].uri
}

output "service_account_email" {
  description = "Email of the dedicated service account."
  value       = google_service_account.witness.email
}

output "pubsub_topic_name" {
  description = "Name of the Pub/Sub topic receiving audit log events."
  value       = google_pubsub_topic.audit_events.name
}

output "log_sink_name" {
  description = "Name of the Log Router sink."
  value       = google_logging_project_sink.audit_to_pubsub.name
}

# Red team #5: Deployment fingerprint
output "deployment_fingerprint" {
  description = "SHA-256 deployment fingerprint for portal verification."
  value = sha256(jsonencode({
    module          = "gcp-cloud-function"
    container_image = var.container_image
    image_digest    = var.container_image_digest
    agent_id        = var.agent_id
    clearing_level  = var.clearing_level
    endpoint        = var.endpoint
    project_id      = var.project_id
    region          = var.region
  }))
}
