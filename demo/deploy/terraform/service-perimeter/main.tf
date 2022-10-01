variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "service_perimeter" {
  description = "Service Perimeter"
  type        = string
}

variable "accesscontextmanager_api" {
  type = object({})
}

data "google_project" "project" {
  project_id     = "vpc-sc-demo-nicholascain15"
}

resource "google_access_context_manager_access_policy" "access-policy" {
  parent = "organizations/${data.google_project.project.org_id}"
  title  = "nick_webhook_15"
  scopes = ["projects/${data.google_project.project.number}"]
  depends_on = [
    var.accesscontextmanager_api
  ]
}


resource "google_access_context_manager_service_perimeter" "service-perimeter" {
  parent = "accessPolicies/${google_access_context_manager_access_policy.access-policy.name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.access-policy.name}/servicePerimeters/${var.service_perimeter}"
  title  = var.service_perimeter
  status {
    resources = [
      "projects/${data.google_project.project.number}",
    ]
    restricted_services = []
  }
}