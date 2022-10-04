variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "access_token" {
  description = "Access Token"
  type        = string
  sensitive = true
}

variable "region" {
  description = "Region"
  type        = string
}

variable "bucket" {
  description = "bucket"
  type        = string
}

variable "vpc_network" {
  description = "VPC Network Name"
  type        = string
  default     = "webhook-net"
}

variable "vpc_subnetwork" {
  description = "Subnetwork for Reverse Proxy Server"
  type        = string
  default     = "webhook-subnet"
}

variable "reverse_proxy_server_ip" {
  description = "IP Address of Reverse Proxy Servier"
  type        = string
  default     = "10.10.20.2"
}

variable "service_directory_namespace" {
  description = "Service Directory Namespace"
  type        = string
  default     = "df-namespace"
}

variable "service_directory_service" {
  description = "Service Directory Service"
  type        = string
  default     = "df-service"
}

variable "service_directory_endpoint" {
  description = "Service Directory Endpoint"
  type        = string
  default     = "df-endpoint"
}

variable "webhook_name" {
  description = "webhook_name"
  type        = string
  default     = "custom-telco-webhook"
}

variable "webhook_src" {
  description = "webhook_src"
  type        = string
  default = "/app/deploy/webhook-src"
}

variable "service_perimeter" {
  description = "Service Perimeter"
  type        = string
  default     = "df_webhook"
}

variable "access_policy_title" {
  description = "Access Policy"
  type        = string
}

provider "google" {
  project     = var.project_id
  billing_project     = var.project_id
  region      = var.region
  user_project_override = true
}

terraform {
  required_providers {
    google = "~> 4.37.0"
  }
  backend "gcs" {
    bucket  = null
    prefix  = null
  }
}

resource "google_project_service" "servicedirectory" {
  service = "servicedirectory.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "compute" {
  service = "compute.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "dialogflow" {
  service = "dialogflow.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "cloudfunctions" {
  service = "cloudfunctions.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "cloudbuild" {
  service = "cloudbuild.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "accesscontextmanager" {
  service = "accesscontextmanager.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "cloudbilling" {
  service = "cloudbilling.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

module "services" {
  source = "/app/deploy/terraform/services"
  project_id = var.project_id
  depends_on = [
    google_project_service.servicedirectory,
    google_project_service.compute,
    google_project_service.dialogflow,
    google_project_service.cloudfunctions,
    google_project_service.cloudbuild,
    google_project_service.accesscontextmanager,
  ]
}

module "vpc_network" {
  source = "/app/deploy/terraform/vpc-network"
  project_id = var.project_id
  region = var.region
  vpc_network = var.vpc_network
  vpc_subnetwork = var.vpc_subnetwork
  reverse_proxy_server_ip = var.reverse_proxy_server_ip
  compute_api = google_project_service.compute
}

module "service_directory" {
  source = "/app/deploy/terraform/service-directory"
  project_id = var.project_id
  region = var.region
  vpc_network = var.vpc_network
  reverse_proxy_server_ip = var.reverse_proxy_server_ip
  service_directory_endpoint = var.service_directory_endpoint
  service_directory_service = var.service_directory_service
  service_directory_namespace = var.service_directory_namespace
  service_directory_service_api = google_project_service.servicedirectory
}

module "webhook_agent" {
  source = "/app/deploy/terraform/webhook-agent"
  project_id = var.project_id
  region = var.region
  access_token = var.access_token
  webhook_src = var.webhook_src
  webhook_name = var.webhook_name
  bucket = var.bucket
  dialogflow_api = google_project_service.dialogflow
  cloudfunctions_api = google_project_service.cloudfunctions
  cloudbuild_api = google_project_service.cloudbuild
}

module "service_perimeter" {
  source = "/app/deploy/terraform/service-perimeter"
  project_id = var.project_id
  service_perimeter = var.service_perimeter
  accesscontextmanager_api = google_project_service.accesscontextmanager
  access_policy_title = var.access_policy_title
  cloudbilling_api = google_project_service.cloudbilling
}