variable "project_id" {
  description = "Project ID"
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

output "project_id" {
  value = var.project_id
}

output "region" {
  value = var.region
}

output "bucket" {
  value = var.bucket
}

resource "google_storage_bucket" "bucket" {
  name     = var.bucket
  location = "US"
  project = var.project_id
}

provider "google" {
  project     = var.project_id
  region      = var.region
}

terraform {
  required_providers {
    google = "~> 3.17.0"
  }
}
