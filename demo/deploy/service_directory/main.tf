variable "bucket" {
  description = "Service Directory Namespace"
  type        = string
}

variable "service_directory_namespace" {
  description = "Service Directory Namespace"
  type        = string
}

variable "service_directory_service" {
  description = "Service Directory Service"
  type        = string
}

variable "service_directory_endpoint" {
  description = "Service Directory Endpoint"
  type        = string
}

variable "reverse_proxy_server_ip" {
  description = "IP Address of Reverse Proxy Servier"
  type        = string
}

variable "vpc_network" {
  description = "VPC Network Name"
  type        = string
}

variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "region" {
  description = "Region"
  type        = string
}

output "service_directory_namespace" {
  value = var.service_directory_namespace
}

output "service_directory_service" {
  value = var.service_directory_service
}

output "service_directory_endpoint" {
  value = var.service_directory_endpoint
}

output "reverse_proxy_server_ip" {
  value = var.reverse_proxy_server_ip
}

output "vpc_network" {
  value = var.vpc_network
}

output "project_id" {
  value = var.project_id
}

output "region" {
  value = var.region
}

provider "google" {
  project     = var.project_id
  region      = var.region
}

terraform {
  required_providers {
    google = "~> 3.17.0"
  }
  backend "gcs" {
    bucket  = null
    prefix  = null
  }
}

data "google_project" "project" {
  project_id     = var.project_id
}

resource "google_service_directory_namespace" "reverse_proxy" {
  provider     = google-beta
  namespace_id = var.service_directory_namespace
  location     = var.region
  project = var.project_id
}

resource "google_service_directory_service" "reverse_proxy" {
  provider   = google-beta
  service_id = var.service_directory_service
  namespace  = google_service_directory_namespace.reverse_proxy.id
}

resource "google_compute_network" "vpc_network" {
  name = var.vpc_network
  project = var.project_id
  auto_create_subnetworks = false
}

resource "google_service_directory_endpoint" "reverse_proxy" {
  provider    = google-beta
  endpoint_id = var.service_directory_endpoint
  service     = google_service_directory_service.reverse_proxy.id
  metadata = {
    stage  = "prod"
    region = var.region
  }
  network = "projects/${data.google_project.project.number}/locations/global/networks/${google_compute_network.vpc_network.name}"
  address = var.reverse_proxy_server_ip
  port    = 443
}
