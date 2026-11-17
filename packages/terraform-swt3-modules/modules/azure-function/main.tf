# SWT3 Infrastructure Witness -- Azure Function Module
#
# Deploys: Function App + Event Grid Subscription + Storage Account
#
# Architecture:
#   Activity Log -> Event Grid -> Azure Function (swt3-infra-witness) -> SWT3 API
#
# The Function reads Azure Activity Log events, extracts canonical fields,
# computes deterministic hashes, and witnesses via the SWT3 protocol.
# Raw audit data never leaves your Azure tenant.

data "azurerm_client_config" "current" {}

locals {
  function_name = "${var.name_prefix}-infra-witness"
  storage_name  = replace("${var.name_prefix}witnessst", "-", "")
  sub_id        = var.subscription_id != "" ? var.subscription_id : data.azurerm_client_config.current.subscription_id
  # Use digest-pinned image if provided (red team #1)
  image = var.container_image_digest != "" ? "${split(":", var.container_image)[0]}@${var.container_image_digest}" : var.container_image

  common_tags = merge(var.tags, {
    "swt3:module" = "azure-function"
  })
}

# --- Storage Account ---
# Required by Azure Functions for runtime state.

resource "azurerm_storage_account" "witness" {
  name                     = substr(local.storage_name, 0, 24)
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.common_tags
}

# --- App Service Plan (Consumption) ---

resource "azurerm_service_plan" "witness" {
  name                = "${var.name_prefix}-witness-plan"
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.common_tags
}

# --- Function App ---
# Runs swt3-infra-witness container in server mode.
# API key fetched from Key Vault at runtime via app settings reference.

resource "azurerm_linux_function_app" "witness" {
  name                       = local.function_name
  resource_group_name        = var.resource_group_name
  location                   = var.location
  service_plan_id            = azurerm_service_plan.witness.id
  storage_account_name       = azurerm_storage_account.witness.name
  storage_account_access_key = azurerm_storage_account.witness.primary_access_key
  tags                       = local.common_tags

  identity {
    type = "SystemAssigned"
  }

  site_config {
    container_registry_use_managed_identity = false

    application_stack {
      docker {
        registry_url = "https://ghcr.io"
        image_name   = "tenova-labs/swt3-infra-witness"
        image_tag    = split(":", var.container_image)[1]
      }
    }
  }

  app_settings = {
    SWT3_ENDPOINT       = var.endpoint
    SWT3_CLEARING_LEVEL = tostring(var.clearing_level)
    SWT3_AGENT_ID       = var.agent_id
    # Key Vault reference -- Function runtime resolves at startup (red team #3)
    SWT3_API_KEY = "@Microsoft.KeyVault(SecretUri=${var.swt3_api_key_vault_id})"
    SWT3_SIGNING_KEY = var.signing_key_vault_id != "" ? "@Microsoft.KeyVault(SecretUri=${var.signing_key_vault_id})" : ""
  }
}

# --- Key Vault Access Policy ---
# Grant the Function App's managed identity access to read secrets.

resource "azurerm_key_vault_access_policy" "witness" {
  key_vault_id = split("/secrets/", var.swt3_api_key_vault_id)[0]
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.witness.identity[0].principal_id

  secret_permissions = ["Get"]
}

# --- Event Grid Subscription ---
# Routes Activity Log events to the Function App.

resource "azurerm_eventgrid_system_topic" "activity_log" {
  name                   = "${var.name_prefix}-activity-log"
  resource_group_name    = var.resource_group_name
  location               = "global"
  source_arm_resource_id = "/subscriptions/${local.sub_id}"
  topic_type             = "Microsoft.Resources.Subscriptions"
  tags                   = local.common_tags
}

resource "azurerm_eventgrid_system_topic_event_subscription" "witness" {
  name                = "${var.name_prefix}-witness-sub"
  system_topic        = azurerm_eventgrid_system_topic.activity_log.name
  resource_group_name = var.resource_group_name

  azure_function_endpoint {
    function_id = "${azurerm_linux_function_app.witness.id}/functions/witness"
  }

  included_event_types = [
    "Microsoft.Resources.ResourceWriteSuccess",
    "Microsoft.Resources.ResourceDeleteSuccess",
    "Microsoft.Resources.ResourceActionSuccess",
  ]
}
