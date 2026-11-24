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

mock_provider "google" {}
mock_provider "google-beta" {}

mock_provider "google" {
  alias = "billing"
}

mock_provider "google-beta" {
  alias = "billing"
}

variables {
  alert_email = "alerts@example.com"
  assured_workloads = {
    regime   = "IL5"
    location = "us"
    folder   = "folders/123456789012"
  }
  automation = {
    outputs_bucket               = "test-outputs-bucket"
    project_id                   = "test-automation"
    project_number               = "123456789012"
    federated_identity_pool      = null
    federated_identity_providers = {}
    service_accounts = {
      resman   = "resman@test-automation.iam.gserviceaccount.com"
      resman-r = "resman-r@test-automation.iam.gserviceaccount.com"
    }
  }
  billing_account = {
    id = "000000-AAAAAA-000000"
  }
  common_services_folder = "folders/123456789012"
  envs_folders = {
    Prod = { admin = "gcp-organization-admins@example.com" }
  }
  fast_features = {
    envs = true
  }
  organization = {
    domain      = "example.com"
    id          = 123456789012
    customer_id = "C00000000"
  }
  prefix = "test"
  regime_mapping = {
    IL5 = "il5"
  }
  regions = {
    primary = "us-east4"
  }
  tenants = {
    app = {
      admin_principal  = "group:gcp-devops@example.com"
      descriptive_name = "Application tenant"
      locations        = { gcs = "us-east4", kms = "us-east4" }
    }
  }
}

run "default_org_iam_mode_preserves_org_bindings" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  assert {
    condition     = length(module.root-folder-iam) == 0
    error_message = "Expected module.root-folder-iam to be omitted when deploy_org_resources.iam is true."
  }

  assert {
    condition = (
      contains(keys(local.iam_bindings_additive), "sa_sec_vpcsc_admin") &&
      local.iam_bindings_additive["sa_sec_vpcsc_admin"].role == "roles/accesscontextmanager.policyAdmin"
    )
    error_message = "Expected default organization IAM mode to retain sa_sec_vpcsc_admin with roles/accesscontextmanager.policyAdmin."
  }

  assert {
    condition     = local.iam_bindings_additive["org-viewer-tenant_app_admin"].role == "roles/resourcemanager.organizationViewer"
    error_message = "Expected default organization IAM mode to grant roles/resourcemanager.organizationViewer to tenant admins."
  }
}

run "folder_iam_mode_strips_org_only_roles" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  variables {
    deploy_org_resources = {
      audit_config            = false
      custom_roles            = false
      iam                     = false
      logging_settings        = false
      logging_sinks           = false
      org_policies            = false
      workforce_identity_pool = false
    }
    fast_features = {
      data_platform   = true
      envs            = true
      gke             = true
      project_factory = true
    }
  }

  assert {
    condition     = length(module.root-folder-iam) == 1 && module.root-folder-iam[0].id == "folders/123456789012"
    error_message = "Expected module.root-folder-iam[0] to target the enclave Assured Workloads folder when deploy_org_resources.iam is false."
  }

  assert {
    condition = (
      !contains(keys(local._root_folder_iam_bindings_additive), "sa_sec_vpcsc_admin") &&
      !contains(
        [for k, v in local._root_folder_iam_bindings_additive : v.role],
        "roles/accesscontextmanager.policyAdmin"
      )
    )
    error_message = "Expected root-folder-iam additive bindings to omit roles/accesscontextmanager.policyAdmin when deploy_org_resources.iam is false."
  }

  assert {
    condition = alltrue([
      for k, v in local._root_folder_iam_bindings_additive :
      !contains(local.org_only_roles, v.role)
    ])
    error_message = "Expected root-folder-iam additive bindings to strip all org_only_roles."
  }

  assert {
    condition = alltrue([
      for key in [
        "sa_net_fw_policy_admin",
        "sa_net_xpn_admin",
        "sa_sec_asset_viewer",
        "org-viewer-tenant_app_admin",
      ] : contains(keys(local._root_folder_iam_bindings_additive), key)
    ])
    error_message = "Expected folder-compatible network, asset, and tenant viewer bindings to remain on root-folder-iam."
  }

  assert {
    condition     = local._root_folder_iam_bindings_additive["org-viewer-tenant_app_admin"].role == "roles/resourcemanager.folderViewer"
    error_message = "Expected folder IAM mode to downgrade tenant viewer bindings to roles/resourcemanager.folderViewer."
  }
}
