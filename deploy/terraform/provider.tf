terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
  }
  backend "s3" {
    # Configure via -backend-config or env: TF_VAR_*
    # bucket = "osmiridium-tfstate"
    # key    = "prod/terraform.tfstate"
    # region = "us-east-1"
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project = "osmiridium"
      ManagedBy = "terraform"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "cluster_name" {
  type    = string
  default = "osmiridium-prod"
}
