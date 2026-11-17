# SWT3 Infrastructure Witness -- GCP Cloud Function Module
#
# Deploys: Cloud Function (gen2) + Pub/Sub + Log Router Sink
#
# Architecture:
#   Cloud Audit Log -> Log Router Sink -> Pub/Sub -> Cloud Function
#     (swt3-infra-witness) -> SWT3 API
#
# The Function reads GCP audit log entries, extracts canonical fields,
# computes deterministic hashes, and witnesses via the SWT3 protocol.
# Raw audit data never leaves your GCP project.

locals {
  function_name = "${var.name_prefix}-infra-witness"
  # Use digest-pinned image if provided (red team #1)
  image = var.container_image_digest != "" ? "${split(":", var.container_image)[0]}@${var.container_image_digest}" : var.container_image

  common_labels = merge(var.labels, {
    "swt3-module" = "gcp-cloud-function"
  })
}

# --- Service Account ---
# Dedicated SA for the Cloud Function with least-privilege access.

resource "google_service_account" "witness" {
  account_id   = "${var.name_prefix}-witness"
  display_name = "SWT3 Infrastructure Witness"
  project      = var.project_id
}

# Grant Secret Manager access to the service account
resource "google_secret_manager_secret_iam_member" "api_key" {
  secret_id = split("/versions/", var.swt3_api_key_secret_id)[0]
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.witness.email}"
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "signing_key" {
  count     = var.signing_key_secret_id != "" ? 1 : 0
  secret_id = split("/versions/", var.signing_key_secret_id)[0]
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.witness.email}"
  project   = var.project_id
}

# --- Pub/Sub Topic + Subscription ---
# Receives audit log events from the Log Router sink.

resource "google_pubsub_topic" "audit_events" {
  name    = "${var.name_prefix}-audit-events"
  project = var.project_id
  labels  = local.common_labels
}

# --- Log Router Sink ---
# Routes Cloud Audit Logs to the Pub/Sub topic.

resource "google_logging_project_sink" "audit_to_pubsub" {
  name        = "${var.name_prefix}-audit-sink"
  project     = var.project_id
  destination = "pubsub.googleapis.com/${google_pubsub_topic.audit_events.id}"
  filter      = var.audit_log_filter

  unique_writer_identity = true
}

# Grant the sink's writer identity permission to publish
resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic   = google_pubsub_topic.audit_events.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.audit_to_pubsub.writer_identity
  project = var.project_id
}

# --- Cloud Function (gen2) ---
# Triggered by Pub/Sub, runs swt3-infra-witness container.

resource "google_cloudfunctions2_function" "witness" {
  name     = local.function_name
  location = var.region
  project  = var.project_id
  labels   = local.common_labels

  build_config {
    runtime     = "go122"
    entry_point = "WitnessHandler"

    # For container-based deployment, use docker_repository
    # For now, the function wraps the binary via a Cloud Run service
    source {
      storage_source {
        # Placeholder -- in production, upload the Go binary as a zip
        # or use the container image via Cloud Run integration
        bucket = ""
        object = ""
      }
    }
  }

  service_config {
    max_instance_count    = var.max_instances
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.witness.email

    environment_variables = {
      SWT3_ENDPOINT       = var.endpoint
      SWT3_CLEARING_LEVEL = tostring(var.clearing_level)
      SWT3_AGENT_ID       = var.agent_id
    }

    # Secret Manager references -- runtime resolves at startup (red team #3)
    secret_environment_variables {
      key        = "SWT3_API_KEY"
      project_id = var.project_id
      secret     = split("/secrets/", split("/versions/", var.swt3_api_key_secret_id)[0])[1]
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.audit_events.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }
}
