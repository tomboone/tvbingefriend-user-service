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

# Project Configuration
variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "project_short_name" {
  description = "Short project name used for resource naming"
  type        = string
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8080
}

# Container Resources
variable "cpu" {
  description = "CPU allocation for the container (in cores)"
  type        = number
  default     = 0.25
}

variable "memory" {
  description = "Memory allocation for the container"
  type        = string
  default     = "0.5Gi"
}

# Scaling Configuration
variable "min_replicas" {
  description = "Minimum number of container replicas"
  type        = number
  default     = 1
}

variable "max_replicas" {
  description = "Maximum number of container replicas"
  type        = number
  default     = 3
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
