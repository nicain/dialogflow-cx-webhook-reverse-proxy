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

output "vpc_subnetwork" {
  value = var.vpc_subnetwork
}

output "reverse_proxy_server_ip" {
  value = var.reverse_proxy_server_ip
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
  backend "gcs" {
    bucket  = "vpc-sc-demo-nicholascain15-tf"
    prefix  = "terraform/state"
  }
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