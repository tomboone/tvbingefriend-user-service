terraform {
  required_version = ">= 1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.57"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    mysql = {
      source  = "petoju/mysql"
      version = "~> 3.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "mysql" {
  endpoint = data.terraform_remote_state.shared.outputs.mysql_server_fqdn
  username = var.mysql_admin_username
  password = var.mysql_admin_password
  tls      = "true"
}
