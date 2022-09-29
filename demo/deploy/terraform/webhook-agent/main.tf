variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "region" {
  description = "Region"
  type        = string
}

variable "access_token" {
  description = "Access Token"
  type        = string
}

variable "webhook_src" {
  description = "webhook_src"
  type        = string
}

variable "webhook_name" {
  description = "webhook_name"
  type        = string
}

variable "bucket" {
  description = "bucket"
  type        = string
}

variable "dialogflow_api" {
  type = object({})
}

variable "cloudfunctions_api" {
  type = object({})
}

variable "cloudbuild_api" {
  type = object({})
}

locals {
	root_dir = abspath("./")
  archive_path = abspath("./tmp/function.zip")
  region = var.region
}

resource "google_storage_bucket" "bucket" {
  name     = var.bucket
  location = "US"
  project = var.project_id
  force_destroy = true
}

data "archive_file" "source" {
  type        = "zip"
  source_dir  = var.webhook_src
  output_path = local.archive_path
}

resource "google_storage_bucket_object" "archive" {
  name   = "index.zip"
  bucket = google_storage_bucket.bucket.name
  source = data.archive_file.source.output_path
  depends_on = [data.archive_file.source]
}

resource "time_sleep" "wait_for_apis" {
  create_duration = "60s"
  depends_on = [
    var.cloudfunctions_api,
    var.cloudbuild_api
  ]
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
  depends_on = [
    time_sleep.wait_for_apis
  ]
}

resource "google_dialogflow_cx_agent" "full_agent" {
  display_name = "Telecommunications"
  location = var.region
  default_language_code = "en"
  time_zone = "America/Chicago"
  project = var.project_id
  enable_spell_correction = true

  provisioner "local-exec" {
    command = "/app/deploy/terraform/webhook-agent/deploy_agent.sh --region=${var.region} --project_id=${var.project_id} --webhook_name=${var.webhook_name} --token=${var.access_token}"
  }
  depends_on = [
    var.dialogflow_api
  ]

}