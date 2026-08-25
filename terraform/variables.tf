variable "project_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "osmiridium"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
  allowed_values = ["dev", "staging", "prod"]
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}