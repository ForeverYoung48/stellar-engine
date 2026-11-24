/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

# tfdoc:file:description Audit log project and sink.

locals {
  all_logging_sinks = merge(
    {
      for name, attrs in var.log_sinks : name => {
        bq_partitioned_table = attrs.type == "bigquery"
        destination          = local.log_sink_destinations[name].id
        exclusions           = attrs.exclusions == null ? {} : attrs.exclusions
        filter               = attrs.filter
        type                 = attrs.type
      }
    },
    {
      for key, cfg in local.siem_export_topics : "siem-${key}" => {
        bq_partitioned_table = false
        destination          = module.siem-export-pubsub[key].id
        exclusions           = cfg.exclusions
        filter               = cfg.filter
        type                 = "pubsub"
      }
    }
  )
  has_pubsub_export = (
    contains(local.log_types, "pubsub") ||
    length(local.siem_export_topics) > 0
  )
  log_export_pubsub_sinks = {
    for k, v in var.log_sinks : k => {
      for sk, sv in(v.subscriptions == null ? {} : v.subscriptions) : sk => {
        ack_deadline_seconds       = sv.ack_deadline_seconds
        expiration_policy_ttl      = sv.expiration_policy_ttl
        message_retention_duration = sv.message_retention_duration
        iam = (
          length(sv.subscribers == null ? [] : sv.subscribers) > 0
          ? { "roles/pubsub.subscriber" = sv.subscribers }
          : {}
        )
      }
    } if v.type == "pubsub"
  }
  log_sink_destinations = merge(
    # use the same dataset for all sinks with `bigquery` as  destination
    {
      for k, v in var.log_sinks :
      k => module.log-export-dataset[0] if v.type == "bigquery"
    },
    # use the same gcs bucket for all sinks with `storage` as destination
    {
      for k, v in var.log_sinks :
      k => module.log-export-gcs[0] if v.type == "storage"
    },
    # use separate pubsub topics and logging buckets for sinks with
    # destination `pubsub` and `logging`
    module.log-export-pubsub,
    module.log-export-logbucket
  )
  log_types = toset([for k, v in var.log_sinks : v.type])
  logging_kms_key = coalesce(
    var.logging_kms_key, module.logging-kms.key_ids["log-sink"]
  )
  siem_export_kms_iam_keys = (
    var.siem_export == null
    ? toset([])
    : (
      coalesce(var.siem_export.manage_kms_iam, true)
      ? toset(compact(values(
        var.siem_export.kms_keys == null
        ? {}
        : var.siem_export.kms_keys
      )))
      : toset([])
    )
  )
  siem_export_topics = var.siem_export == null ? {} : {
    for pair in setproduct(
      keys(var.siem_export.tiers),
      var.siem_export.regions
      ) : "${pair[0]}-${pair[1]}" => {
      exclusions = (
        var.siem_export.tiers[pair[0]].exclusions == null
        ? {}
        : var.siem_export.tiers[pair[0]].exclusions
      )
      filter = var.siem_export.tiers[pair[0]].filter
      kms_key = (
        try(var.siem_export.kms_keys[pair[1]], null) != null
        ? var.siem_export.kms_keys[pair[1]]
        : (pair[1] == local.locations.kms ? local.logging_kms_key : null)
      )
      region = pair[1]
      subscriptions = {
        "siem-${pair[0]}-${pair[1]}-sub" = {
          ack_deadline_seconds  = var.siem_export.ack_deadline_seconds
          expiration_policy_ttl = var.siem_export.expiration_policy_ttl
          message_retention_duration = (
            var.siem_export.message_retention_duration
          )
          iam = (
            length(
              var.siem_export.tiers[pair[0]].subscribers == null
              ? []
              : var.siem_export.tiers[pair[0]].subscribers
            ) > 0
            ? {
              "roles/pubsub.subscriber" = (
                var.siem_export.tiers[pair[0]].subscribers
              )
            }
            : {}
          )
        }
      }
      tier = pair[0]
    }
  }
}

module "log-export-project" {
  source                  = "../../../modules/project"
  name                    = "audit-logs-0"
  default_service_account = "deprivilege"
  deletion_policy         = var.project_deletion_policies.logging
  lien_reason             = "Protected by default as a core project."
  parent = coalesce(
    var.project_parent_ids.logging, module.branch-common-services-folder.folder.name
  )
  prefix          = local.prefix
  billing_account = var.billing_account.id
  contacts = (
    var.bootstrap_user != null ? {} : local.essential_contacts
  )
  iam = {
    "roles/owner"  = [module.automation-tf-bootstrap-sa.iam_email]
    "roles/viewer" = [module.automation-tf-bootstrap-r-sa.iam_email]
  }
  services = concat(
    [
      # "cloudresourcemanager.googleapis.com",
      # "iam.googleapis.com",
      # "serviceusage.googleapis.com",
      "bigquery.googleapis.com",
      "storage.googleapis.com",
      "stackdriver.googleapis.com",
      "cloudkms.googleapis.com",
      "pubsub.googleapis.com",
      "compute.googleapis.com",
      "logging.googleapis.com"
    ],
    var.monitoring_project != null ? ["monitoring.googleapis.com"] : []
  )
  depends_on = [module.organization-logging]
}

# Read project-level Cloud Logging settings to provision the project's
# CMEK service agent before granting KMS permissions and creating CMEK buckets.
data "google_logging_project_settings" "log_export" {
  count      = contains(local.log_types, "logging") ? 1 : 0
  project    = module.log-export-project.project_id
  depends_on = [module.log-export-project]
}

moved {
  from = google_compute_project_metadata.metadata-log-export
  to   = google_compute_project_metadata.metadata_log_export
}

resource "google_compute_project_metadata" "metadata_log_export" {
  project = module.log-export-project.project_id
  metadata = {
    block-project-ssh-keys = "TRUE" # CIS Compliance Benchmark 4.3
    enable-oslogin         = "TRUE" # CIS Compliance Benchmark 4.4
  }
}

# one log export per type, with conditionals to skip those not needed

module "log-export-dataset" {
  source         = "../../../modules/bigquery-dataset"
  count          = contains(local.log_types, "bigquery") ? 1 : 0
  project_id     = module.log-export-project.project_id
  id             = "logs"
  friendly_name  = "Audit logs export."
  location       = local.locations.bq
  encryption_key = local.logging_kms_key
  depends_on     = [module.logging-kms]
}

module "log-export-gcs" {
  source         = "../../../modules/gcs"
  count          = contains(local.log_types, "storage") ? 1 : 0
  project_id     = module.log-export-project.project_id
  name           = "logs"
  prefix         = local.prefix
  location       = local.locations.gcs
  storage_class  = local.gcs_storage_class
  force_destroy  = var.force_destroy
  encryption_key = local.logging_kms_key
  depends_on     = [module.logging-kms]
}

module "log-export-logbucket" {
  source        = "../../../modules/logging-bucket"
  for_each      = toset([for k, v in var.log_sinks : k if v.type == "logging"])
  parent_type   = "project"
  parent        = module.log-export-project.project_id
  name          = each.key
  location      = local.locations.logging
  log_analytics = { enable = true }
  kms_key_name  = local.logging_kms_key
  retention     = var.logging_bucket_retention
  # org-level and project-level logging settings ready before we create any logging buckets
  depends_on = [
    module.organization-logging,
    module.logging-kms,
    data.google_logging_project_settings.log_export,
  ]
}

module "log-export-pubsub" {
  source        = "../../../modules/pubsub"
  for_each      = local.log_export_pubsub_sinks
  project_id    = module.log-export-project.project_id
  name          = each.key
  regions       = local.locations.pubsub
  kms_key       = local.logging_kms_key
  subscriptions = each.value
  depends_on    = [module.logging-kms]
}

resource "google_kms_crypto_key_iam_member" "siem_export_pubsub" {
  for_each      = local.siem_export_kms_iam_keys
  crypto_key_id = each.key
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member = (
    module.log-export-project.service_agents["pubsub"].iam_email
  )
}

module "siem-export-pubsub" {
  source        = "../../../modules/pubsub"
  for_each      = local.siem_export_topics
  project_id    = module.log-export-project.project_id
  name          = "siem-${each.key}"
  regions       = [each.value.region]
  kms_key       = each.value.kms_key
  subscriptions = each.value.subscriptions
  depends_on = [
    module.logging-kms,
    google_kms_crypto_key_iam_member.siem_export_pubsub,
  ]
}
