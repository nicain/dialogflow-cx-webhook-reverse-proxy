

variable "access_token" {
  description = "Access Token"
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

output "access_token" {
  value = var.access_token
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

resource "google_storage_bucket" "bucket" {
  name     = var.bucket
  location = "US"
  project = var.project_id
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

resource "google_storage_bucket_object" "archive" {
  name   = "index.zip"
  bucket = google_storage_bucket.bucket.name
  source = data.archive_file.source.output_path
  depends_on = [data.archive_file.source, google_storage_bucket.bucket]
}

resource "google_cloudfunctions_function" "function" {
  project = var.project_id
  name        = var.webhook_name
  description = "VPC-SC Demo Webhook"
  runtime     = "python39"
  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket.bucket.name
  source_archive_object = google_storage_bucket_object.archive.name
  trigger_http          = true
  timeout               = 60
  entry_point           = "cxPrebuiltAgentsTelecom"
  region = var.region
  depends_on = [google_storage_bucket_object.archive, google_project_service.service]
}

resource "google_project_service" "service" {
  for_each = toset([
    "cloudresourcemanager.googleapis.com",
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
