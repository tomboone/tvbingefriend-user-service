output "container_app_name" {
  description = "Name of the container app"
  value       = azurerm_container_app.user_service.name
}

output "container_app_fqdn" {
  description = "FQDN of the container app"
  value       = azurerm_container_app.user_service.ingress[0].fqdn
}

output "container_app_url" {
  description = "Full URL of the container app"
  value       = "https://${azurerm_container_app.user_service.ingress[0].fqdn}"
}

output "database_name" {
  description = "Name of the MySQL database"
  value       = azurerm_mysql_flexible_database.main.name
}

output "database_user" {
  description = "Database username"
  value       = mysql_user.main.user
}
