variable "vpc_network" {
  description = "VPC Network Name"
  type        = string
}

variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "access_token" {
  description = "Access Token"
  type        = string
}

variable "region" {
  description = "Region"
  type        = string
}

output "vpc_network" {
  value = var.vpc_network
}

output "project_id" {
  value = var.project_id
}

output "access_token" {
  value = var.access_token
}

output "region" {
  value = var.region
}

provider "google" {
  project     = var.project_id
  region      = var.region
  access_token = var.access_token
}

terraform {
  required_providers {
    google = "~> 3.17.0"
  }
}

resource "google_compute_network" "vpc_network" {
  name = var.vpc_network
  project = var.project_id
  auto_create_subnetworks = false
}
