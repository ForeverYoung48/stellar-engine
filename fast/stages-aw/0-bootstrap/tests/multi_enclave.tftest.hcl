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
          resource_id   = "222222222222"
          resource_type = "CONSUMER_FOLDER"
        }
      ]
    }
  }
  mock_data "google_logging_project_settings" {
    defaults = {
      kms_service_account_id     = "service-123456789012@gcp-sa-logging.iam.gserviceaccount.com"
      logging_service_account_id = "service-123456789012@gcp-sa-logging.iam.gserviceaccount.com"
    }
  }
}

mock_provider "google-beta" {}
mock_provider "local" {}
mock_provider "time" {}

variables {
  alert_email = "alerts@example.com"
  assured_workloads = {
    regime   = "IL5"
    location = "us-east4"
  }
  billing_account = {
    id = "000000-AAAAAA-000000"
  }
  bootstrap_project    = "my-bootstrap-project"
  kms_protection_level = "HSM"
  organization = {
    customer_id = "C00000000"
    domain      = "example.com"
    id          = 123456789012
  }
  prefix = "acme"
  regions = {
    primary = "us-east4"
  }
}

run "default_env_preserves_prod_naming" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  assert {
    condition     = local.prefix == "acme-prod"
    error_message = "Expected default local.prefix to remain acme-prod."
  }

  assert {
    condition     = module.automation-project.project_id == "acme-prod-iac-core-0"
    error_message = "Expected default automation project ID to remain acme-prod-iac-core-0."
  }

  assert {
    condition     = module.log-export-project.project_id == "acme-prod-audit-logs-0"
    error_message = "Expected default log export project ID to remain acme-prod-audit-logs-0."
  }

  assert {
    condition     = module.billing-export-project[0].project_id == "acme-prod-billing-exp-0"
    error_message = "Expected default billing export project ID to remain acme-prod-billing-exp-0."
  }

  assert {
    condition     = module.automation-tf-bootstrap-gcs.name == "acme-prod-iac-core-bootstrap-0"
    error_message = "Expected default bootstrap state bucket name to remain acme-prod-iac-core-bootstrap-0."
  }

  assert {
    condition     = module.automation-tf-output-gcs.name == "acme-prod-iac-core-outputs-0"
    error_message = "Expected default outputs bucket name to remain acme-prod-iac-core-outputs-0."
  }

  assert {
    condition     = module.automation-tf-resman-gcs.name == "acme-prod-iac-core-resman-0"
    error_message = "Expected default resman state bucket name to remain acme-prod-iac-core-resman-0."
  }

  assert {
    condition     = module.automation-tf-bootstrap-sa.email == "acme-prod-bootstrap-0@acme-prod-iac-core-0.iam.gserviceaccount.com"
    error_message = "Expected default bootstrap service account email to preserve prod naming."
  }

  assert {
    condition     = module.automation-tf-resman-sa.email == "acme-prod-resman-0@acme-prod-iac-core-0.iam.gserviceaccount.com"
    error_message = "Expected default resman service account email to preserve prod naming."
  }

  assert {
    condition     = local.gcs_kms_resman_sa == "serviceAccount:acme-prod-resman-0@acme-prod-iac-core-0.iam.gserviceaccount.com"
    error_message = "Expected default GCS KMS admin binding to target prod resman SA."
  }

  assert {
    condition     = google_assured_workloads_workload.primary[0].display_name == "StellarEngine-acme"
    error_message = "Expected default Assured Workloads display name to remain StellarEngine-acme."
  }

  assert {
    condition     = length(module.root-folder-config) == 0
    error_message = "Expected root-folder-config to remain disabled when org resources are enabled."
  }

  assert {
    condition     = length(module.organization-logging) == 1
    error_message = "Expected organization-logging to deploy by default."
  }

  assert {
    condition     = length(google_organization_iam_audit_config.organization) == 1 && length(google_folder_iam_audit_config.folder) == 0
    error_message = "Expected org-level audit config to deploy by default."
  }
}

run "custom_env_dev_isolates_resource_names" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    env = "dev"
  }

  assert {
    condition     = local.prefix == "acme-dev"
    error_message = "Expected local.prefix to use custom env value dev."
  }

  assert {
    condition     = module.automation-project.project_id == "acme-dev-iac-core-0"
    error_message = "Expected automation project ID to be prefixed with acme-dev."
  }

  assert {
    condition     = module.log-export-project.project_id == "acme-dev-audit-logs-0"
    error_message = "Expected log export project ID to be prefixed with acme-dev."
  }

  assert {
    condition     = module.billing-export-project[0].project_id == "acme-dev-billing-exp-0"
    error_message = "Expected billing export project ID to be prefixed with acme-dev."
  }

  assert {
    condition     = module.automation-tf-bootstrap-gcs.name == "acme-dev-iac-core-bootstrap-0"
    error_message = "Expected bootstrap state bucket to be prefixed with acme-dev."
  }

  assert {
    condition     = module.automation-tf-output-gcs.name == "acme-dev-iac-core-outputs-0"
    error_message = "Expected outputs bucket to be prefixed with acme-dev."
  }

  assert {
    condition     = module.automation-tf-resman-gcs.name == "acme-dev-iac-core-resman-0"
    error_message = "Expected resman state bucket to be prefixed with acme-dev."
  }

  assert {
    condition     = module.automation-tf-bootstrap-sa.email == "acme-dev-bootstrap-0@acme-dev-iac-core-0.iam.gserviceaccount.com"
    error_message = "Expected bootstrap service account to use acme-dev."
  }

  assert {
    condition     = module.automation-tf-resman-sa.email == "acme-dev-resman-0@acme-dev-iac-core-0.iam.gserviceaccount.com"
    error_message = "Expected resman service account to use acme-dev."
  }

  assert {
    condition     = local.gcs_kms_resman_sa == "serviceAccount:acme-dev-resman-0@acme-dev-iac-core-0.iam.gserviceaccount.com"
    error_message = "Expected GCS KMS admin binding to target acme-dev resman SA."
  }

  assert {
    condition     = local.gcs_kms_resman_r_sa == "serviceAccount:acme-dev-resman-0r@acme-dev-iac-core-0.iam.gserviceaccount.com"
    error_message = "Expected GCS KMS viewer binding to target acme-dev read-only resman SA."
  }

  assert {
    condition     = google_assured_workloads_workload.primary[0].display_name == "StellarEngine-acme-dev"
    error_message = "Expected non-prod Assured Workloads display name to include env token."
  }
}

run "enclave_only_mode_plans_zero_org_mutations" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  override_resource {
    target          = google_assured_workloads_workload.primary[0]
    override_during = plan
    values = {
      resources = [
        {
          resource_id   = "222222222222"
          resource_type = "CONSUMER_FOLDER"
        }
      ]
    }
  }

  variables {
    env = "dev"
    billing_account = {
      id           = "000000-AAAAAA-000000"
      is_org_level = true
      no_iam       = true
    }
    deploy_org_resources = {
      audit_config            = false
      custom_roles            = false
      iam                     = false
      logging_settings        = false
      logging_sinks           = false
      org_policies            = false
      workforce_identity_pool = false
    }
    workforce_identity_pool = {
      display_name = "dev-workforce-pool"
    }
  }

  assert {
    condition     = length(module.organization-logging) == 0
    error_message = "Expected zero organization-logging modules in enclave-only mode."
  }

  assert {
    condition     = length(google_organization_iam_audit_config.organization) == 0
    error_message = "Expected zero organization IAM audit configs in enclave-only mode."
  }

  assert {
    condition     = length(google_folder_iam_audit_config.folder) == 1 && google_folder_iam_audit_config.folder[0].folder == "folders/222222222222"
    error_message = "Expected folder IAM audit config to attach strictly to the enclave folder."
  }

  assert {
    condition     = length(google_iam_workforce_pool.default) == 0
    error_message = "Expected zero organization workforce pools in enclave-only mode."
  }

  assert {
    condition     = length(module.organization.custom_roles) == 0 && length(module.organization.custom_constraint_ids) == 0
    error_message = "Expected zero organization custom roles or custom constraints in enclave-only mode."
  }

  assert {
    condition     = length(module.organization.organization_policies_ids) == 0
    error_message = "Expected zero organization-level org policies in enclave-only mode."
  }

  assert {
    condition     = length(module.organization.logging_sinks) == 0 && length(module.organization.sink_writer_identities) == 0
    error_message = "Expected zero organization-level log sinks in enclave-only mode."
  }

  assert {
    condition     = length(module.root-folder-config) == 1 && module.root-folder-config[0].id == "folders/222222222222"
    error_message = "Expected module.root-folder-config to attach strictly to the enclave Assured Workloads folder."
  }

  assert {
    condition     = length(module.root-folder-config[0].sink_writer_identities) == length(var.log_sinks)
    error_message = "Expected folder-level log sinks to be planned on the enclave folder."
  }

  assert {
    condition     = length(module.root-folder-config[0].organization_policies_ids) > 0
    error_message = "Expected folder-level org policies to attach to the enclave folder."
  }

  assert {
    condition     = length(module.billing-export-project) == 0
    error_message = "Expected enclave-only mode with billing_account.no_iam = true to skip billing export project."
  }
}

run "enclave_only_mode_unknown_folder_plans_cleanly" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    env = "dev"
    billing_account = {
      id           = "000000-AAAAAA-000000"
      is_org_level = true
      no_iam       = true
    }
    deploy_org_resources = {
      audit_config            = false
      custom_roles            = false
      iam                     = false
      logging_settings        = false
      logging_sinks           = false
      org_policies            = false
      workforce_identity_pool = false
    }
  }

  assert {
    condition     = length(module.root-folder-config) == 1 && length(google_folder_iam_audit_config.folder) == 1
    error_message = "Expected enclave-only mode to plan cleanly even before the Assured Workloads folder ID is known."
  }
}

run "enclave_only_no_compliance_folder_uses_env" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    env = "dev"
    assured_workloads = {
      regime   = "COMPLIANCE_REGIME_UNSPECIFIED"
      location = "us-east4"
    }
    deploy_org_resources = {
      audit_config            = false
      custom_roles            = false
      iam                     = false
      logging_settings        = false
      logging_sinks           = false
      org_policies            = false
      workforce_identity_pool = false
    }
  }

  assert {
    condition     = length(module.no-compliance-folder) == 1 && local.enclave_display_name == "StellarEngine-acme-dev"
    error_message = "Expected fallback no-compliance folder to use the env-scoped display name."
  }
}

run "max_length_prefix_and_env_respect_gcp_limits" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    prefix = "abcdefg"
    env    = "nonprd"
  }

  assert {
    condition     = length(module.automation-project.project_id) <= 30
    error_message = "Expected automation project ID length to stay within 30 characters."
  }

  assert {
    condition     = length(module.log-export-project.project_id) <= 30
    error_message = "Expected log export project ID length to stay within 30 characters."
  }

  assert {
    condition     = length(module.billing-export-project[0].project_id) <= 30
    error_message = "Expected billing export project ID length to stay within 30 characters."
  }

  assert {
    condition     = length("${local.prefix}-bootstrap-0r") <= 30
    error_message = "Expected longest Stage 0 service account ID length to stay within 30 characters."
  }

  assert {
    condition     = length(local.enclave_display_name) <= 30
    error_message = "Expected enclave folder display name to stay within 30 characters."
  }
}

run "reject_uppercase_env" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    env = "DEV"
  }

  expect_failures = [
    var.env,
  ]
}

run "reject_spaces_in_env" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    env = "dev 1"
  }

  expect_failures = [
    var.env,
  ]
}

run "reject_too_long_env" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    env = "staging"
  }

  expect_failures = [
    var.env,
  ]
}

run "reject_trailing_hyphen_env" {
  command = plan

  providers = {
    google      = google
    google-beta = google-beta
    local       = local
    time        = time
  }

  variables {
    env = "dev-"
  }

  expect_failures = [
    var.env,
  ]
}
