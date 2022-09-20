
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

variable "webhook_name" {
  description = "webhook_name"
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

output "webhook_name" {
  value = var.webhook_name
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

resource "google_storage_bucket_object" "archive" {
  name   = "index.zip"
  bucket = var.bucket
  source = data.archive_file.source.output_path
  depends_on = [data.archive_file.source]
}

resource "google_cloudfunctions_function" "function" {
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
