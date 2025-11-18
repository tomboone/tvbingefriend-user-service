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

# Create MySQL database
resource "azurerm_mysql_flexible_database" "main" {
  name                = var.project_short_name
  resource_group_name = data.terraform_remote_state.shared.outputs.mysql_server_resource_group_name
  server_name         = data.terraform_remote_state.shared.outputs.mysql_server_name
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
  user               = "${var.project_short_name}_user"
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

locals {
  app_env_vars = {
    ENVIRONMENT    = "production"
    DB_HOST        = data.terraform_remote_state.shared.outputs.mysql_server_fqdn
    DB_PORT        = "3306"
    DB_NAME        = azurerm_mysql_flexible_database.main.name
    DB_USER        = mysql_user.main.user
    DB_PASSWORD    = random_password.db_password.result
    JWT_SECRET     = var.jwt_secret
    ALLOWED_ORIGIN = join(",", var.allowed_origins)
    SMTP_HOST      = var.smtp_host
    SMTP_PORT      = "587"
    SMTP_USERNAME  = var.smtp_username
    SMTP_PASSWORD  = var.smtp_password
    EMAIL_FROM     = var.email_from
    APP_URL        = var.app_url
  }
}

# Create container app
resource "azurerm_container_app" "user_service" {
  name                         = var.project_name
  container_app_environment_id = data.terraform_remote_state.shared.outputs.container_app_environment_id
  resource_group_name          = data.terraform_remote_state.shared.outputs.app_service_plan_resource_group
  revision_mode                = "Single"

  # Registry credentials from shared infrastructure
  secret {
    name  = "registry-password"
    value = data.terraform_remote_state.shared.outputs.acr_admin_password
  }

  registry {
    server               = data.terraform_remote_state.shared.outputs.acr_login_server
    username             = data.terraform_remote_state.shared.outputs.acr_admin_username
    password_secret_name = "registry-password"
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = var.project_name
      image  = "${data.terraform_remote_state.shared.outputs.acr_login_server}/${var.project_name}:latest"
      cpu    = var.cpu
      memory = var.memory

      # Dynamic environment variables from app_env_vars
      dynamic "env" {
        for_each = local.app_env_vars
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = var.container_port
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}