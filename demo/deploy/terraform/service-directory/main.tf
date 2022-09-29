variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "region" {
  description = "Region"
  type        = string
}

variable "vpc_network" {
  description = "VPC Network"
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
  description = "reverse_proxy_server_ip"
  type        = string
}

variable "service_directory_service_api" {
  type = object({})
}

data "google_project" "project" {
  project_id     = var.project_id
}

resource "google_service_directory_namespace" "reverse_proxy" {
  provider     = google-beta
  namespace_id = var.service_directory_namespace
  location     = var.region
  project = var.project_id
  depends_on = [
    var.service_directory_service_api
  ]
}

resource "google_service_directory_service" "reverse_proxy" {
  provider   = google-beta
  service_id = var.service_directory_service
  namespace  = google_service_directory_namespace.reverse_proxy.id
}

resource "google_service_directory_endpoint" "reverse_proxy" {
  provider    = google-beta
  endpoint_id = var.service_directory_endpoint
  service     = google_service_directory_service.reverse_proxy.id
  metadata = {
    stage  = "prod"
    region = var.region
  }
  network = "projects/${data.google_project.project.number}/locations/global/networks/${var.vpc_network}"
  address = var.reverse_proxy_server_ip
  port    = 443
}