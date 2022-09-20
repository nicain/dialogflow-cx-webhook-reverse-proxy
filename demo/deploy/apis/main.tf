variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "region" {
  description = "Region"
  type        = string
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
    bucket  = "vpc-sc-demo-nicholascain15-tf"
    prefix  = "terraform/apis"
  }
}

resource "google_project_service" "service" {
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
