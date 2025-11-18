locals {
  service_name = "tvbf-user-service"
  short_svc_name = "tvbfusersvc"
}

# Reference shared infrastructure
data "terraform_remote_state" "shared" {
  backend = "azurerm"
  config = {
    resource_group_name  = var.tf_shared_resource_group_name
    storage_account_name = var.tf_shared_storage_account_name
    container_name       = var.tf_shared_container_name
    key                  = var.tf_shared_key
  }
}

data "azurerm_resource_group" "existing" {
  name = data.terraform_remote_state.shared.outputs.resource_group_name
}

data "azurerm_storage_account" "existing" {
  name                     = data.terraform_remote_state.shared.outputs.storage_account_name
  resource_group_name      = data.terraform_remote_state.shared.outputs.resource_group_name
}

data "azurerm_container_registry" "existing" {
  name                = data.terraform_remote_state.shared.outputs.acr_name
  resource_group_name = data.terraform_remote_state.shared.outputs.acr_rg_name
}

data "azurerm_mysql_flexible_server" "existing" {
  name                = data.terraform_remote_state.shared.outputs.mysql_server_name
  resource_group_name = data.terraform_remote_state.shared.outputs.mysql_server_resource_group_name
}

data "azurerm_log_analytics_workspace" "existing" {
  name                = data.terraform_remote_state.shared.outputs.log_analytics_workspace_name
  resource_group_name = data.terraform_remote_state.shared.outputs.log_analytics_workspace_resource_group_name
}

data "azurerm_container_app_environment" "existing" {
  name                = data.terraform_remote_state.shared.outputs.container_app_environment_name
  resource_group_name = data.terraform_remote_state.shared.outputs.container_app_environment_resource_group_name
}

# Create MySQL database
resource "azurerm_mysql_flexible_database" "main" {
  name                = local.short_svc_name
  resource_group_name = data.azurerm_mysql_flexible_server.existing.resource_group_name
  server_name         = data.azurerm_mysql_flexible_server.existing.name
  charset             = "utf8mb4"
  collation           = "utf8mb4_unicode_ci"
}

# Generate random passwords for database users
resource "random_password" "db_password" {
  length  = 32
  special = false
}

# Create MySQL user for production
resource "mysql_user" "main" {
  user               = "${local.short_svc_name}_user"
  host               = "%"
  plaintext_password = random_password.db_password.result
}

# Grant permissions to production user
resource "mysql_grant" "main" {
  user       = mysql_user.main.user
  host       = mysql_user.main.host
  database   = azurerm_mysql_flexible_database.main.name
  privileges = ["ALL PRIVILEGES"]
}

# Create container app
resource "azurerm_container_app" "user_service" {
  name                         = local.service_name
  container_app_environment_id = data.azurerm_container_app_environment.existing.id
  resource_group_name          = data.azurerm_resource_group.existing.name
  revision_mode                = "Single"

  template {
    container {
      name   = "user-service"
      image  = "${data.azurerm_container_registry.existing.login_server}/user-service:latest"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name  = "ENVIRONMENT"
        value = "production"
      }
      env {
        name  = "DB_HOST"
        value = data.azurerm_mysql_flexible_server.existing.fqdn
      }
      env {
        name = "DB_PORT"
        value = "3306"
      }
      env {
        name  = "DB_NAME"
        value = azurerm_mysql_flexible_database.main.name
      }
      env {
        name  = "DB_USER"
        value = mysql_user.main.user
      }
      env {
        name  = "DB_PASSWORD"
        value = random_password.db_password.result
      }
      env {
        name  = "JWT_SECRET"
        value = var.jwt_secret
      }
      env {
        name  = "ALLOWED_ORIGIN"
        value = var.allowed_origins
      }
      env {
        name  = "SMTP_HOST"
        value = var.smtp_host
      }
      env {
        name = "SMTP_PORT"
        value = "587"
      }
      env {
        name  = "SMTP_USERNAME"
        value = var.smtp_username
      }
      env {
        name  = "SMTP_PASSWORD"
        value = var.smtp_password
      }
      env {
        name  = "EMAIL_FROM"
        value = var.email_from
      }
      env {
        name  = "APP_URL"
        value = var.app_url
      }
      # Add other env vars: SMTP_HOST, SMTP_USERNAME, etc.
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}