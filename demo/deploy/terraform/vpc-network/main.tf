variable "project_id" {
  description = "Project ID"
  type        = string
}

variable "access_token" {
  description = "Access Token"
  type        = string
  sensitive = true
}

variable "webhook_name" {
  description = "webhook_name"
  type        = string
}

variable "region" {
  description = "Region"
  type        = string
}

variable "vpc_subnetwork" {
  description = "VPC Subnetwork"
  type        = string
  default     = "webhook-subnet"
}

variable "vpc_network" {
  description = "VPC Network"
  type        = string
  default     = "webhook-net"
}

variable "proxy_server_src" {
  description = "proxy_server_src"
  type        = string
}

variable "reverse_proxy_server_ip" {
  description = "reverse_proxy_server_ip"
  type        = string
  default     = "10.10.20.2"
}

variable "compute_api" {
  type = object({})
}

variable "bucket" {
  type = object({})
}

variable "iam_api" {
  type = object({})
}

variable "dialogflow_api" {
  type = object({})
}

variable "bucket_name" {
  description = "bucket_name"
  type        = string
}

resource "google_compute_network" "vpc_network" {
  name = var.vpc_network
  project = var.project_id
  auto_create_subnetworks = false
  depends_on = [
    var.compute_api
  ]
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
    ports    = ["443", "3389", "22"]
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

data "google_project" "project" {
  project_id     = var.project_id
}

data "archive_file" "proxy_server_source" {
  type        = "zip"
  source_dir  = var.proxy_server_src
  output_path = abspath("./tmp/server.zip")
}

resource "google_storage_bucket_object" "proxy_server_source" {
  name   = "server.zip"
  bucket = var.bucket_name
  source = data.archive_file.proxy_server_source.output_path
  depends_on = [
    var.bucket
  ]
}

resource "google_pubsub_topic" "reverse_proxy_server_build" {
  name = "build"
}

resource "google_artifact_registry_repository" "webhook_registry" {
  location      = var.region
  repository_id = "webhook-registry"
  format        = "DOCKER"
  project       = var.project_id
}

resource "google_cloudbuild_trigger" "reverse_proxy_server" {

  pubsub_config {
    topic = google_pubsub_topic.reverse_proxy_server_build.id
  }

  build {
    source {
      storage_source {
        bucket = var.bucket_name
        object = google_storage_bucket_object.proxy_server_source.name
      }
    }
    
    logs_bucket = "gs://${var.bucket_name}"

    step {
      name = "gcr.io/cloud-builders/docker"
      timeout = "120s"
      args = ["build", "--network", "cloudbuild", "--no-cache", "-t", "${var.region}-docker.pkg.dev/${var.project_id}/webhook-registry/webhook-server-image:latest", "."]
    }
    artifacts {
      images = ["${var.region}-docker.pkg.dev/${var.project_id}/webhook-registry/webhook-server-image:latest"]
    }
  }
  depends_on = [
    google_artifact_registry_repository.webhook_registry,
    var.bucket
  ]

  provisioner "local-exec" {
    command = "export CLOUDSDK_AUTH_ACCESS_TOKEN=${var.access_token} && gcloud --project=${var.project_id} pubsub topics publish build --message=build"
  }
}

resource "time_sleep" "wait_for_build" {
  create_duration = "60s"
  depends_on = [
    google_cloudbuild_trigger.reverse_proxy_server
  ]
}

resource "google_project_service_identity" "dfsa" {
  provider = google-beta
  project = var.project_id
  service = "dialogflow.googleapis.com"
  depends_on = [
    var.iam_api,
    var.dialogflow_api,
  ]
}

resource "google_project_iam_member" "dfsa_sd_viewer" {
  project = var.project_id
  role               = "roles/servicedirectory.viewer"
  member = "serviceAccount:${google_project_service_identity.dfsa.email}"
}

resource "google_project_iam_member" "dfsa_sd_pscAuthorizedService" {
  project = var.project_id
  role               = "roles/servicedirectory.pscAuthorizedService"
  member = "serviceAccount:${google_project_service_identity.dfsa.email}"
}

resource "google_compute_instance" "reverse_proxy_server" {
  name         = "webhook-server"
  project      =  var.project_id
  zone         = "${var.region}-a"
  machine_type = "n1-standard-1"
  tags = ["webhook-reverse-proxy-vm"]
  service_account {
    scopes = ["cloud-platform"]
  }

  boot_disk {
    auto_delete = true
    device_name = "instance-1"
    mode = "READ_WRITE"
    initialize_params {
      image = "projects/debian-cloud/global/images/debian-10-buster-v20220719"
      size = 10
    }
  }

  network_interface {
    network = google_compute_network.vpc_network.name
    subnetwork = google_compute_subnetwork.reverse_proxy_subnetwork.name
    network_ip = google_compute_address.reverse_proxy_address.address
  }

  metadata = {
    bucket = var.bucket_name
    image = "${var.region}-docker.pkg.dev/${var.project_id}/webhook-registry/webhook-server-image:latest"
    bot_user = google_project_service_identity.dfsa.email
    webhook_trigger_uri = "https://${var.region}-${var.project_id}.cloudfunctions.net/${var.webhook_name}"
  }

  metadata_startup_script = file("${path.module}/startup_script.sh")

  provisioner "local-exec" {
    command = "/app/deploy/terraform/vpc-network/wait_until_server_ready.sh --zone=${self.zone} --project_id=${var.project_id}  --token=${var.access_token}"
  }
  depends_on = [
    time_sleep.wait_for_build,
    var.bucket,
    google_project_iam_member.dfsa_sd_viewer,
    google_project_iam_member.dfsa_sd_pscAuthorizedService,
  ]
  
}