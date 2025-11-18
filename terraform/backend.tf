terraform {
  backend "azurerm" {
    # Backend configuration should be provided via:
    # 1. Command line: terraform init -backend-config=backend.hcl
    # 2. Environment variables
    # 3. Or specified here (not recommended for sensitive values)

    # Example backend.hcl:
    # resource_group_name  = "tfstate-rg"
    # storage_account_name = "tfstatesa"
    # container_name       = "tfstate"
    # key                  = "recommendation-service.tfstate"
  }
}
