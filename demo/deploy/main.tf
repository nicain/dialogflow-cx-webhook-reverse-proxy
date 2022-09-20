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

variable "bucket" {
  description = "bucket"
  type        = string
}

variable "vpc_network" {
  description = "VPC Network Name"
  type        = string
}

variable "vpc_subnetwork" {
  description = "Subnetwork for Reverse Proxy Server"
  type        = string
}

variable "reverse_proxy_server_ip" {
  description = "IP Address of Reverse Proxy Servier"
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

variable "webhook_name" {
  description = "webhook_name"
  type        = string
}

provider "google" {
  project     = var.project_id
  region      = var.region
  user_project_override = true
}

data "google_project" "project" {
  project_id     = var.project_id
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

resource "google_project_service" "services" {
  for_each = toset([
    "cloudfunctions.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "dialogflow.googleapis.com",
    "servicedirectory.googleapis.com",
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudfunctions.googleapis.com",
    "artifactregistry.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "vpcaccess.googleapis.com",
    "appengine.googleapis.com",
  ])
  service = each.key
  project            = var.project_id
  disable_on_destroy = true
  disable_dependent_services = true
}

resource "google_storage_bucket" "bucket" {
  name     = var.bucket
  location = "US"
  project = var.project_id
  force_destroy = true
}

resource "google_compute_network" "vpc_network" {
  name = var.vpc_network
  project = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_router" "nat_router" {
  name                          = "nat-router"
  network                       = google_compute_network.vpc_network.name
  region = var.region
}

resource "google_compute_router_nat" "nat_manual" {
  name   = "nat-config"
  router = google_compute_router.nat_router.name
  region = google_compute_router.nat_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  log_config {
    enable = true
    filter = "ALL"
  }
}

resource "google_compute_firewall" "allow_dialogflow" {
  name    = "allow-dialogflow"
  network = google_compute_network.vpc_network.name
  direction = "INGRESS"
  priority = 1000
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["35.199.192.0/19"]
  target_tags = ["webhook-reverse-proxy-vm"]
}

resource "google_compute_firewall" "allow" {
  name    = "allow"
  network = google_compute_network.vpc_network.name
  allow {
    protocol = "tcp"
    ports    = ["443", "3389"]
  }
  allow {
    protocol = "icmp"
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_subnetwork" "reverse_proxy_subnetwork" {
  name          = var.vpc_subnetwork
  ip_cidr_range = "10.10.20.0/28"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.vpc_network.name
  private_ip_google_access = true
}

resource "google_compute_address" "reverse_proxy_address" {
  name         = "webhook-reverse-proxy-address"
  subnetwork   = google_compute_subnetwork.reverse_proxy_subnetwork.id
  address_type = "INTERNAL"
  purpose      = "GCE_ENDPOINT"
  region       = var.region
  address      = var.reverse_proxy_server_ip
}

locals {
	root_dir = abspath("./")
  archive_path = abspath("./tmp/function.zip")
  region = var.region
}

data "archive_file" "source" {
  type        = "zip"
  source_dir  = abspath("./webhook")
  output_path = local.archive_path
}

resource "google_storage_bucket_object" "archive" {
  name   = "index.zip"
  bucket = var.bucket
  source = data.archive_file.source.output_path
  depends_on = [data.archive_file.source]
}

resource "google_cloudfunctions_function" "webhook" {
  project = var.project_id
  name        = var.webhook_name
  description = "VPC-SC Demo Webhook"
  runtime     = "python39"
  available_memory_mb   = 128
  source_archive_bucket = var.bucket
  source_archive_object = google_storage_bucket_object.archive.name
  trigger_http          = true
  timeout               = 60
  entry_point           = "cxPrebuiltAgentsTelecom"
  region = var.region
  depends_on = [google_storage_bucket_object.archive]
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

resource "google_dialogflow_cx_agent" "full_agent" {
  display_name = "Telecommunications"
  location = var.region
  default_language_code = "en"
  time_zone = "America/Chicago"
  project = var.project_id

  provisioner "local-exec" {
    command = "./deploy_agent.sh -r=${var.region} -p=${var.project_id} -w=${var.webhook_name} -t=${var.access_token}"
  }

}