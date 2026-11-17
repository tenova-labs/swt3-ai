# Outputs for the SWT3 Azure Function module.

output "function_app_name" {
  description = "Name of the Azure Function App."
  value       = azurerm_linux_function_app.witness.name
}

output "function_app_id" {
  description = "Resource ID of the Azure Function App."
  value       = azurerm_linux_function_app.witness.id
}

output "function_app_url" {
  description = "Default hostname of the Function App."
  value       = "https://${azurerm_linux_function_app.witness.default_hostname}"
}

output "managed_identity_principal_id" {
  description = "Principal ID of the Function App's managed identity (for Key Vault access)."
  value       = azurerm_linux_function_app.witness.identity[0].principal_id
}

output "event_grid_topic_id" {
  description = "Resource ID of the Event Grid system topic."
  value       = azurerm_eventgrid_system_topic.activity_log.id
}

# Red team #5: Deployment fingerprint
output "deployment_fingerprint" {
  description = "SHA-256 deployment fingerprint for portal verification."
  value = sha256(jsonencode({
    module          = "azure-function"
    container_image = var.container_image
    image_digest    = var.container_image_digest
    agent_id        = var.agent_id
    clearing_level  = var.clearing_level
    endpoint        = var.endpoint
    location        = var.location
    subscription_id = local.sub_id
  }))
}
