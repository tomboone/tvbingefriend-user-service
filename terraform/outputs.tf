# Root-level outputs for recommendation service
output "database_name" {
  description = "Name of the database"
  value       = azurerm_mysql_flexible_database.main.name
}

output "database_url" {
  description = "Database connection URL for use by pipeline"
  value       = "mysql+pymysql://${mysql_user.main.user}:${random_password.db_password.result}@${data.azurerm_mysql_flexible_server.existing.fqdn}/${azurerm_mysql_flexible_database.main.name}"
  sensitive   = true
}

# API outputs
output "function_app_name" {
  description = "Name of the recommendation API function app"
  value       = module.recommendation_api.function_app_name
}

output "function_app_url" {
  description = "URL of the recommendation API"
  value       = module.recommendation_api.function_app_url
}

output "function_app_id" {
  description = "Resource ID of the function app"
  value       = module.recommendation_api.function_app_id
}

output "function_app_resource_group_name" {
  description = "Resource group name of the function app"
  value       = module.recommendation_api.function_app_resource_group_name
}

output "function_app_python_version" {
  description = "Python version of the function app"
  value       = module.recommendation_api.function_app_python_version
}

# Pipeline outputs
output "container_group_name" {
  description = "Name of the pipeline container group"
  value       = module.recommendation_pipeline.container_group_name
}

output "container_group_id" {
  description = "Resource ID of the pipeline container group"
  value       = module.recommendation_pipeline.container_group_id
}

output "container_group_location" {
  description = "Location of the pipeline container group"
  value = module.recommendation_pipeline.container_group_location
}

# Logic App Scheduler outputs
output "logic_app_name" {
  description = "Name of the Logic App scheduler"
  value       = module.logic_app_scheduler.logic_app_name
}

output "logic_app_id" {
  description = "ID of the Logic App scheduler"
  value       = module.logic_app_scheduler.logic_app_id
}

output "logic_app_access_endpoint" {
  description = "Access endpoint of the Logic App"
  value       = module.logic_app_scheduler.logic_app_access_endpoint
}
