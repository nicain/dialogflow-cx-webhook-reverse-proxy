variable "project_id" {
  description = "Project ID"
  type        = string
}

resource "google_project_service" "run" {
  service = "run.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "artifactregistry" {
  service = "artifactregistry.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "vpcaccess" {
  service = "vpcaccess.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}

resource "google_project_service" "appengine" {
  service = "appengine.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
  disable_dependent_services = true
}
