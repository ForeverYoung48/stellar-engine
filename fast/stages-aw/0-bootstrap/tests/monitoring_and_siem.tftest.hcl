# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

mock_provider "google" {
  mock_resource "google_assured_workloads_workload" {
    defaults = {
      resources = [
        {
          resource_id   = "123456789012"
          resource_type = "CONSUMER_FOLDER"
        }
      ]
    }
  }
  mock_resource "google_folder" {
    defaults = {
      id   = "folders/123456789012"
      name = "folders/123456789012"
    }
  }
  mock_resource "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
  mock_resource "google_kms_crypto_key" {
    defaults = {
      id = "projects/test-prod-audit-logs-0/locations/us-east4/keyRings/logging/cryptoKeys/log-sink"
    }
  }
  mock_data "google_logging_project_settings" {
    defaults = {
      kms_service_account_id = "service-123456789012@gcp-sa-logging.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_logging_organization_sink" {
    defaults = {
      writer_identity = "serviceAccount:service-org-123456789012@gcp-sa-logging.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_logging_folder_sink" {
    defaults = {
      writer_identity = "serviceAccount:service-folder-123456789012@gcp-sa-logging.iam.gserviceaccount.com"
    }
  }
}

mock_provider "google-beta" {
  mock_resource "google_folder" {
    defaults = {
      id   = "folders/123456789012"
      name = "folders/123456789012"
    }
  }
  mock_resource "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
}

variables {
  alert_email = "alerts@example.com"
  assured_workloads = {
    regime   = "IL5"
    location = "us-east4"
  }
  billing_account = {
    id = "000000-AAAAAA-000000"
  }
  bootstrap_project    = "test-bootstrap-0"
  kms_protection_level = "HSM"
  organization = {
    customer_id = "C00000000"
    domain      = "example.com"
    id          = 123456789012
  }
  prefix = "test"
  regions = {
    primary = "us-east4"
  }
}

run "default_config_is_backward_compatible" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  assert {
    condition     = length(module.monitoring-project) == 0
    error_message = "Default configuration must not create a monitoring project."
  }

  assert {
    condition     = length(google_monitoring_monitored_project.default) == 0
    error_message = "Default configuration must not create monitored project links."
  }

  assert {
    condition     = output.monitoring_project_id == null
    error_message = "monitoring_project_id output must be null when disabled."
  }

  assert {
    condition     = !contains(keys(local.tfvars), "monitoring_project_id")
    error_message = "local.tfvars must omit monitoring_project_id so 0-bootstrap.auto.tfvars.json stays unchanged."
  }

  assert {
    condition     = length(module.siem-export-pubsub) == 0
    error_message = "Default configuration must not create SIEM Pub/Sub topics."
  }

  assert {
    condition     = length(google_kms_crypto_key_iam_member.siem_export_pubsub) == 0
    error_message = "Default configuration must not create external SIEM KMS IAM bindings."
  }

  assert {
    condition     = length(output.siem_export) == 0
    error_message = "siem_export output must be empty when disabled."
  }

  assert {
    condition     = !local.has_pubsub_export
    error_message = "Default configuration must not enable Pub/Sub KMS bindings."
  }

  assert {
    condition     = contains(module.automation-project.services, "monitoring.googleapis.com")
    error_message = "Automation project must enable monitoring.googleapis.com."
  }

  assert {
    condition = (
      !contains(local.billing_export_services, "monitoring.googleapis.com") &&
      !contains(module.log-export-project.services, "monitoring.googleapis.com")
    )
    error_message = "Default configuration must preserve billing-export and log-export service lists when monitoring_project is null."
  }
}

run "monitoring_project_enabled_scopes_core_and_extra_projects" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    monitoring_project = {
      name                = "monitoring-0"
      scope_core_projects = true
      monitored_projects = [
        "extra-workload-0",
        "test-prod-monitoring-0",
      ]
    }
  }

  assert {
    condition     = length(module.monitoring-project) == 1
    error_message = "Enabled monitoring_project must provision one project module."
  }

  assert {
    condition     = local._monitoring_deletion_policy == "DELETE"
    error_message = "Monitoring project deletion_policy must coalesce to project_deletion_policies.monitoring ('DELETE') by default."
  }

  assert {
    condition = (
      contains(local.billing_export_services, "monitoring.googleapis.com") &&
      contains(module.log-export-project.services, "monitoring.googleapis.com") &&
      contains(module.automation-project.services, "monitoring.googleapis.com")
    )
    error_message = "Enabling monitoring_project must enable monitoring.googleapis.com on core projects."
  }

  assert {
    condition     = output.monitoring_project_id == "test-prod-monitoring-0"
    error_message = "monitoring_project_id output must match the created scoping project ID."
  }

  assert {
    condition     = !contains(keys(local.tfvars), "monitoring_project_id")
    error_message = "local.tfvars must omit monitoring_project_id to avoid undeclared downstream variable warnings."
  }

  assert {
    condition     = output.project_ids.monitoring == "test-prod-monitoring-0"
    error_message = "project_ids.monitoring must export the scoping project ID."
  }

  assert {
    condition = toset(module.monitoring-project[0].services) == toset([
      "logging.googleapis.com",
      "monitoring.googleapis.com",
    ])
    error_message = "Monitoring project must enable only monitoring and logging APIs."
  }

  assert {
    condition = toset(keys(google_monitoring_monitored_project.default)) == toset([
      "extra-workload-0",
      "test-prod-audit-logs-0",
      "test-prod-billing-exp-0",
      "test-prod-iac-core-0",
    ])
    error_message = "Monitoring scope must attach core projects and extra projects while excluding self."
  }

  assert {
    condition = alltrue([
      for k, v in google_monitoring_monitored_project.default :
      v.metrics_scope == "test-prod-monitoring-0" && v.name == k
    ])
    error_message = "Each monitored project link must target the central monitoring project."
  }
}

run "monitoring_project_without_core_projects" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    monitoring_project = {
      scope_core_projects = false
      monitored_projects  = ["only-workload-0"]
    }
  }

  assert {
    condition     = toset(keys(google_monitoring_monitored_project.default)) == toset(["only-workload-0"])
    error_message = "Disabling scope_core_projects must attach only explicit monitored_projects."
  }
}

run "monitoring_project_inherits_stage_deletion_policy_and_parent" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    bootstrap_user     = "admin@example.com"
    monitoring_project = {}
    project_deletion_policies = {
      monitoring = "ABANDON"
    }
    project_parent_ids = {
      monitoring = "folders/999999999999"
    }
  }

  assert {
    condition     = local._monitoring_deletion_policy == "ABANDON"
    error_message = "Monitoring project must inherit project_deletion_policies.monitoring when monitoring_project.deletion_policy is unset."
  }

  assert {
    condition     = local._monitoring_parent == "folders/999999999999"
    error_message = "Monitoring project must inherit project_parent_ids.monitoring when monitoring_project.parent_id is unset."
  }
}

run "monitoring_project_explicit_policy_and_parent_override_stage_defaults" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    monitoring_project = {
      deletion_policy = "PREVENT"
      parent_id       = "folders/888888888888"
    }
    project_deletion_policies = {
      monitoring = "ABANDON"
    }
    project_parent_ids = {
      monitoring = "folders/999999999999"
    }
  }

  assert {
    condition     = local._monitoring_deletion_policy == "PREVENT"
    error_message = "Explicit monitoring_project.deletion_policy must override project_deletion_policies.monitoring."
  }

  assert {
    condition     = local._monitoring_parent == "folders/888888888888"
    error_message = "Explicit monitoring_project.parent_id must override project_parent_ids.monitoring."
  }
}

run "log_sinks_exclusions_and_pubsub_subscriptions" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    log_sinks = {
      audit-logs = {
        filter = "logName:\"cloudaudit.googleapis.com\""
        type   = "logging"
        exclusions = {
          exclude-noise = "protoPayload.methodName=\"health.check\""
        }
      }
      security-events = {
        filter = "logName:\"cloudaudit.googleapis.com\""
        type   = "pubsub"
        exclusions = {
          exclude-reads = "protoPayload.methodName=\"storage.objects.get\""
        }
        subscriptions = {
          siem-pull = {
            ack_deadline_seconds       = 90
            message_retention_duration = "259200s"
            subscribers = [
              "serviceAccount:siem-reader@my-project.iam.gserviceaccount.com"
            ]
          }
          audit-pull = {}
        }
      }
    }
  }

  assert {
    condition     = local.has_pubsub_export
    error_message = "Pub/Sub log sink must enable Pub/Sub KMS bindings."
  }

  assert {
    condition = (
      local.all_logging_sinks["audit-logs"].exclusions == tomap({
        exclude-noise = "protoPayload.methodName=\"health.check\""
      }) &&
      one([
        for e in module.organization.logging_sinks["audit-logs"].exclusions :
        e.filter if e.name == "exclude-noise"
      ]) == "protoPayload.methodName=\"health.check\""
    )
    error_message = "Logging sink exclusions must forward into the organization log sink."
  }

  assert {
    condition = (
      local.all_logging_sinks["security-events"].exclusions == tomap({
        exclude-reads = "protoPayload.methodName=\"storage.objects.get\""
      }) &&
      one([
        for e in module.organization.logging_sinks["security-events"].exclusions :
        e.filter if e.name == "exclude-reads"
      ]) == "protoPayload.methodName=\"storage.objects.get\""
    )
    error_message = "Pub/Sub sink exclusions must forward into the organization log sink."
  }

  assert {
    condition = (
      module.log-export-pubsub["security-events"].subscriptions["siem-pull"].ack_deadline_seconds == 90 &&
      module.log-export-pubsub["security-events"].subscriptions["siem-pull"].message_retention_duration == "259200s" &&
      module.log-export-pubsub["security-events"].subscriptions["siem-pull"].expiration_policy[0].ttl == ""
    )
    error_message = "Custom subscription attributes and non-expiring TTL must wire to module.log-export-pubsub."
  }

  assert {
    condition = (
      module.log-export-pubsub["security-events"].subscriptions["audit-pull"].ack_deadline_seconds == 60 &&
      module.log-export-pubsub["security-events"].subscriptions["audit-pull"].message_retention_duration == "604800s" &&
      module.log-export-pubsub["security-events"].subscriptions["audit-pull"].expiration_policy[0].ttl == ""
    )
    error_message = "Subscription defaults including non-expiring TTL must apply when attributes are omitted."
  }

  assert {
    condition = (
      toset(keys(local.log_export_pubsub_sinks["security-events"]["siem-pull"].iam)) == toset(["roles/pubsub.subscriber"]) &&
      toset(local.log_export_pubsub_sinks["security-events"]["siem-pull"].iam["roles/pubsub.subscriber"]) == toset([
        "serviceAccount:siem-reader@my-project.iam.gserviceaccount.com"
      ])
    )
    error_message = "Subscribers must receive subscription-scoped roles/pubsub.subscriber IAM."
  }

  assert {
    condition     = length(local.log_export_pubsub_sinks["security-events"]["audit-pull"].iam) == 0
    error_message = "Subscriptions without subscribers must not create IAM bindings."
  }
}

run "siem_export_multi_tier_multi_region_composite_keys" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  override_resource {
    target          = module.log-export-project.google_project.project[0]
    override_during = plan
    values = {
      number = "123456789012"
    }
  }

  override_resource {
    target          = module.logging-kms.google_kms_crypto_key.default["log-sink"]
    override_during = plan
    values = {
      id = "projects/test-prod-audit-logs-0/locations/us-east4/keyRings/logging/cryptoKeys/log-sink"
    }
  }

  variables {
    siem_export = {
      regions = ["us-east4", "us-west1"]
      kms_keys = {
        "us-west1" = "projects/my-project/locations/us-west1/keyRings/siem/cryptoKeys/pubsub"
      }
      tiers = {
        tier-1 = {
          filter = "logName:\"cloudaudit.googleapis.com\""
          exclusions = {
            exclude-reads = "protoPayload.methodName=\"storage.objects.get\""
          }
          subscribers = [
            "serviceAccount:siem-t1@my-project.iam.gserviceaccount.com"
          ]
        }
        tier-2 = {
          filter = "resource.type=\"gce_firewall_rule\""
          subscribers = [
            "serviceAccount:siem-t2@my-project.iam.gserviceaccount.com"
          ]
        }
      }
    }
  }

  assert {
    condition     = local.has_pubsub_export
    error_message = "Enabled siem_export must enable Pub/Sub KMS bindings even when default log_sinks use logging buckets."
  }

  assert {
    condition = toset(keys(module.siem-export-pubsub)) == toset([
      "tier-1-us-east4",
      "tier-1-us-west1",
      "tier-2-us-east4",
      "tier-2-us-west1",
    ])
    error_message = "Multi-region siem_export must key topics by composite '<tier>-<region>' keys."
  }

  assert {
    condition = toset(keys(output.siem_export)) == toset([
      "tier-1-us-east4",
      "tier-1-us-west1",
      "tier-2-us-east4",
      "tier-2-us-west1",
    ])
    error_message = "siem_export output must expose all four composite keys."
  }

  assert {
    condition = (
      module.siem-export-pubsub["tier-1-us-east4"].topic.name == "siem-tier-1-us-east4" &&
      toset(module.siem-export-pubsub["tier-1-us-east4"].topic.message_storage_policy[0].allowed_persistence_regions) == toset(["us-east4"]) &&
      module.siem-export-pubsub["tier-1-us-east4"].topic.kms_key_name == local.logging_kms_key &&
      module.siem-export-pubsub["tier-1-us-west1"].topic.name == "siem-tier-1-us-west1" &&
      toset(module.siem-export-pubsub["tier-1-us-west1"].topic.message_storage_policy[0].allowed_persistence_regions) == toset(["us-west1"]) &&
      module.siem-export-pubsub["tier-1-us-west1"].topic.kms_key_name == "projects/my-project/locations/us-west1/keyRings/siem/cryptoKeys/pubsub"
    )
    error_message = "Each SIEM Pub/Sub topic must match its region persistence policy and regional KMS key."
  }

  assert {
    condition = (
      module.siem-export-pubsub["tier-1-us-east4"].subscriptions["siem-tier-1-us-east4-sub"].ack_deadline_seconds == 60 &&
      module.siem-export-pubsub["tier-1-us-east4"].subscriptions["siem-tier-1-us-east4-sub"].message_retention_duration == "604800s" &&
      module.siem-export-pubsub["tier-1-us-east4"].subscriptions["siem-tier-1-us-east4-sub"].expiration_policy[0].ttl == ""
    )
    error_message = "SIEM pull subscriptions must configure retention, ack deadline, and non-expiring TTL."
  }

  assert {
    condition = (
      toset(keys(local.siem_export_topics["tier-1-us-west1"].subscriptions["siem-tier-1-us-west1-sub"].iam)) == toset(["roles/pubsub.subscriber"]) &&
      toset(local.siem_export_topics["tier-1-us-west1"].subscriptions["siem-tier-1-us-west1-sub"].iam["roles/pubsub.subscriber"]) == toset([
        "serviceAccount:siem-t1@my-project.iam.gserviceaccount.com"
      ])
    )
    error_message = "SIEM subscriptions must bind roles/pubsub.subscriber at the subscription level."
  }

  assert {
    condition = alltrue([
      for k in ["siem-tier-1-us-east4", "siem-tier-1-us-west1", "siem-tier-2-us-east4", "siem-tier-2-us-west1"] :
      contains(keys(local.all_logging_sinks), k) && local.all_logging_sinks[k].type == "pubsub"
    ])
    error_message = "Each SIEM tier-region pair must wire a matching pubsub log sink."
  }

  assert {
    condition = (
      local.all_logging_sinks["siem-tier-1-us-west1"].exclusions == tomap({
        exclude-reads = "protoPayload.methodName=\"storage.objects.get\""
      }) &&
      one([
        for e in module.organization.logging_sinks["siem-tier-1-us-west1"].exclusions :
        e.filter if e.name == "exclude-reads"
      ]) == "protoPayload.methodName=\"storage.objects.get\""
    )
    error_message = "SIEM tier exclusions must propagate to every regional SIEM log sink."
  }
  assert {
    condition = (
      toset(keys(google_kms_crypto_key_iam_member.siem_export_pubsub)) == toset([
        "projects/my-project/locations/us-west1/keyRings/siem/cryptoKeys/pubsub"
      ]) &&
      google_kms_crypto_key_iam_member.siem_export_pubsub["projects/my-project/locations/us-west1/keyRings/siem/cryptoKeys/pubsub"].role == "roles/cloudkms.cryptoKeyEncrypterDecrypter" &&
      google_kms_crypto_key_iam_member.siem_export_pubsub["projects/my-project/locations/us-west1/keyRings/siem/cryptoKeys/pubsub"].member == module.log-export-project.service_agents["pubsub"].iam_email
    )
    error_message = "External regional SIEM KMS keys must grant cryptoKeyEncrypterDecrypter to the log-export Pub/Sub service agent when manage_kms_iam is true."
  }
}

run "siem_export_manage_kms_iam_false_skips_external_kms_iam" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    siem_export = {
      manage_kms_iam = false
      regions        = ["us-east4", "us-west1"]
      kms_keys = {
        "us-west1" = "projects/my-project/locations/us-west1/keyRings/siem/cryptoKeys/pubsub"
      }
      tiers = {
        tier-1 = {
          filter = "logName:\"cloudaudit.googleapis.com\""
        }
      }
    }
  }

  assert {
    condition     = length(google_kms_crypto_key_iam_member.siem_export_pubsub) == 0
    error_message = "Setting manage_kms_iam = false must omit google_kms_crypto_key_iam_member.siem_export_pubsub."
  }
}

run "siem_export_folder_scoped_sinks" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    deploy_org_resources = {
      logging_sinks = false
    }
    siem_export = {
      regions = ["us-east4"]
      tiers = {
        tier-1 = {
          filter = "logName:\"cloudaudit.googleapis.com\""
        }
      }
    }
  }

  assert {
    condition     = contains(keys(local.all_logging_sinks), "siem-tier-1-us-east4")
    error_message = "Folder-scoped logging_sinks mode must still wire SIEM sinks cleanly."
  }
}

run "siem_export_rejects_missing_regional_kms_key" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    siem_export = {
      regions = ["us-east4", "us-west1"]
      tiers = {
        tier-1 = {
          filter = "logName:\"cloudaudit.googleapis.com\""
        }
      }
    }
  }

  expect_failures = [
    var.siem_export,
  ]
}

run "siem_export_rejects_mismatched_kms_key_region" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    siem_export = {
      regions = ["us-west1"]
      kms_keys = {
        "us-west1" = "projects/my-project/locations/us-east4/keyRings/siem/cryptoKeys/pubsub"
      }
      tiers = {
        tier-1 = {
          filter = "logName:\"cloudaudit.googleapis.com\""
        }
      }
    }
  }

  expect_failures = [
    var.siem_export,
  ]
}

run "log_sinks_rejects_subscriptions_on_non_pubsub_sink" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    log_sinks = {
      audit-logs = {
        filter = ""
        type   = "logging"
        subscriptions = {
          invalid-sub = {}
        }
      }
    }
  }

  expect_failures = [
    var.log_sinks,
  ]
}

run "monitoring_project_rejects_invalid_deletion_policy" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    monitoring_project = {
      deletion_policy = "DESTROY"
    }
  }

  expect_failures = [
    var.monitoring_project,
  ]
}

run "siem_export_rejects_unanchored_kms_key" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    siem_export = {
      regions = ["us-west1"]
      kms_keys = {
        "us-west1" = "invalid/locations/us-west1/keyRings/siem/cryptoKeys/pubsub"
      }
      tiers = {
        tier-1 = {
          filter = "logName:\"cloudaudit.googleapis.com\""
        }
      }
    }
  }

  expect_failures = [
    var.siem_export,
  ]
}

run "siem_export_rejects_out_of_range_ack_deadline" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    siem_export = {
      ack_deadline_seconds = 5
      regions              = ["us-east4"]
      tiers = {
        tier-1 = {
          filter = "logName:\"cloudaudit.googleapis.com\""
        }
      }
    }
  }

  expect_failures = [
    var.siem_export,
  ]
}

run "log_sinks_rejects_out_of_range_ack_deadline" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
  }

  variables {
    log_sinks = {
      security-events = {
        filter = ""
        type   = "pubsub"
        subscriptions = {
          siem-pull = {
            ack_deadline_seconds = 601
          }
        }
      }
    }
  }

  expect_failures = [
    var.log_sinks,
  ]
}
