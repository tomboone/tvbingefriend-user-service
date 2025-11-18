# Shared infrastructure state
variable "tf_shared_resource_group_name" {
  description = "Resource group name for shared Terraform state"
  type        = string
}

variable "tf_shared_storage_account_name" {
  description = "Storage account name for shared Terraform state"
  type        = string
}

variable "tf_shared_container_name" {
  description = "Container name for shared Terraform state"
  type        = string
}

variable "tf_shared_key" {
  description = "State file key for shared infrastructure"
  type        = string
}

# Environment variables
variable "allowed_origins" {
  description = "Allowed CORS origins for the API"
  type        = list(string)
}

variable "jwt_secret" {
  description = "Secret key for JWT signing"
  type        = string
  sensitive   = true
}

variable "smtp_host" {
  description = "Host name for SMTP server"
  type        = string
  sensitive   = true
}

variable "smtp_username" {
  description = "Username for SMTP server"
  type        = string
}

variable "smtp_password" {
  description = "Password for SMTP server"
  type        = string
  sensitive   = true
}

variable "email_from" {
  description = "Sender email address"
  type        = string
}

variable "app_url" {
  description = "Front end application URL"
  type        = string
}

# MySQL Flexible Server root user
variable "mysql_admin_username" {
  description = "Admin username for MySQL server"
  type        = string
}

variable "mysql_admin_password" {
  description = "Admin password for MySQL server"
  type        = string
  sensitive   = true
}
