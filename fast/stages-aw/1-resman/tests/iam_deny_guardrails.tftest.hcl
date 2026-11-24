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
    Dev  = { admin = "gcp-devops@example.com" }
    Int  = { admin = "gcp-devops@example.com" }
    Test = { admin = "gcp-devops@example.com" }
    Prod = { admin = "gcp-organization-admins@example.com" }
  }
  fast_features = {
    envs            = true
    gke             = true
    project_factory = true
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
    alpha = {
      admin_principal  = "group:alpha-admins@example.com"
      descriptive_name = "Tenant Alpha"
    }
    beta = {
      admin_principal  = "group:beta-admins@example.com"
      descriptive_name = "Tenant Beta"
    }
  }
}

run "disabled_by_default" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  assert {
    condition = (
      alltrue([
        for k, v in local._tenant_iam_deny_policies : length(v) == 0
      ]) &&
      !contains(keys(local._tenant_folder_iam["Prod-alpha"]), "roles/iam.denyReviewer") &&
      !contains(keys(local._network_folder_iam), "roles/iam.denyReviewer")
    )
    error_message = "Expected zero tenant IAM Deny policies and zero denyReviewer bindings when iam_deny_guardrails.enabled is false."
  }
}

run "enabled_defaults_consolidate_single_policy_and_grant_readonly_reviewers" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  variables {
    iam_deny_guardrails = {
      enabled = true
      exception_principals = [
        "principalSet://goog/group/breakglass@example.com",
      ]
      env_exception_principals = {
        Dev  = ["principalSet://goog/group/dev-admins@example.com"]
        Int  = ["principalSet://goog/group/int-admins@example.com"]
        Test = ["principalSet://goog/group/test-admins@example.com"]
        Prod = ["principalSet://goog/group/prod-admins@example.com"]
      }
    }
  }

  # Consolidates enabled rules into 1 single policy per (env, tenant) folder;
  # sa_impersonation_lockdown defaults to false so default rule count is 3.
  assert {
    condition = alltrue([
      for k, policies in local._tenant_iam_deny_policies : (
        toset(keys(policies)) == toset(["tenant-baseline-lockdown"]) &&
        length(policies["tenant-baseline-lockdown"].rules) == 3
      )
    ])
    error_message = "Expected single consolidated tenant-baseline-lockdown policy with 3 rules by default when enabled."
  }

  # Read-only plan SAs receive roles/iam.denyReviewer (and tagViewer on Networking).
  assert {
    condition = (
      local._tenant_folder_iam["Prod-alpha"]["roles/iam.denyReviewer"] == tolist([
        "serviceAccount:resman-r@test-automation.iam.gserviceaccount.com",
      ]) &&
      contains(
        local._network_folder_iam["roles/iam.denyReviewer"],
        module.branch-network-r-sa.iam_email
      ) &&
      contains(
        local._network_folder_iam["roles/resourcemanager.tagViewer"],
        module.branch-network-r-sa.iam_email
      )
    )
    error_message = "Expected resman-r and networking-r to receive IAM Deny and tag viewer roles when enabled."
  }

  # Canonical non-prod environments (Dev, Int, Test) all receive *-dev-sa
  # exemptions and never receive *-prod-sa exemptions.
  assert {
    condition = alltrue([
      for env_key in ["Dev-alpha", "Int-alpha", "Test-alpha"] : (
        contains(
          local._tenant_iam_deny_policies[env_key]["tenant-baseline-lockdown"].rules[2].exception_principals,
          "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-gke-dev-sa[0].email}"
        ) &&
        !contains(
          local._tenant_iam_deny_policies[env_key]["tenant-baseline-lockdown"].rules[2].exception_principals,
          "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-gke-prod-sa[0].email}"
        ) &&
        contains(
          local._tenant_deny_automation_static_exceptions[env_key],
          "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-pf-dev-sa[0].email}"
        ) &&
        !contains(
          local._tenant_deny_automation_static_exceptions[env_key],
          "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-pf-prod-sa[0].email}"
        )
      )
    ])
    error_message = "Expected Dev, Int, and Test folders to exempt non-prod branch SAs only."
  }

  # Prod receives *-prod-sa only and remains isolated from non-prod and other tenants.
  assert {
    condition = (
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-gke-prod-sa[0].email}"
      ) &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].exception_principals,
        "principalSet://goog/group/prod-admins@example.com"
      ) &&
      !contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-gke-dev-sa[0].email}"
      ) &&
      !contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.tenant-core-sa["Prod-beta"].email}"
      )
    )
    error_message = "Expected Prod-alpha exception principals to stay isolated from non-prod and other tenants."
  }

  # KMS rules split destructive verbs (base exceptions only) from KMS IAM
  # and metadata mutations (which also exempt env automation SAs and self-iac SA).
  assert {
    condition = (
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[0].denied_permissions,
        "cloudkms.googleapis.com/cryptoKeyVersions.destroy"
      ) &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[0].denied_permissions,
        "cloudkms.googleapis.com/cryptoKeyVersions.update"
      ) &&
      !contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[0].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.tenant-self-iac-sa["Prod-alpha"].email}"
      ) &&
      !contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[0].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-pf-prod-sa[0].email}"
      ) &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[1].denied_permissions,
        "cloudkms.googleapis.com/cryptoKeys.setIamPolicy"
      ) &&
      contains(
        local._tenant_deny_automation_static_exceptions["Prod-alpha"],
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.tenant-self-iac-sa["Prod-alpha"].email}"
      ) &&
      contains(
        local._tenant_deny_automation_static_exceptions["Prod-alpha"],
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.branch-pf-prod-sa[0].email}"
      )
    )
    error_message = "Expected consolidated policy to separate KMS destructive verbs from CMEK IAM/metadata mutations."
  }

  assert {
    condition = (
      length(local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].denied_permissions) == 32 &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].denied_permissions,
        "gkehub.googleapis.com/memberships.create"
      ) &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].denied_permissions,
        "gkehub.googleapis.com/rbacrolebindings.create"
      ) &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].denied_permissions,
        "gkehub.googleapis.com/namespaces.create"
      ) &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[2].denied_permissions,
        "gkehub.googleapis.com/gateway.post"
      )
    )
    error_message = "Expected full verified GKE Hub fleet, namespace, RBAC, and gateway denied permissions."
  }
}

run "enabled_all_four_rules_and_single_sa_lockdown_rule" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  variables {
    iam_deny_guardrails = {
      enabled                       = true
      kms_iam_lockdown              = true
      kms_key_destruction           = true
      sa_impersonation_lockdown     = true
      tenant_gke_fleet_registration = true
      sa_impersonation_tag = {
        key   = "111111111111/scope"
        value = "platform"
      }
    }
  }

  assert {
    condition = (
      keys(local._tenant_iam_deny_policies["Prod-alpha"]) == tolist(["tenant-baseline-lockdown"]) &&
      length(local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules) == 4 &&
      local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[3].denial_condition.expression == "resource.matchTag('111111111111/scope', 'platform')" &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[3].denied_permissions,
        "iam.googleapis.com/serviceAccounts.actAs"
      ) &&
      contains(
        local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[3].denied_permissions,
        "iam.googleapis.com/serviceAccountKeys.create"
      ) &&
      contains(
        local._tenant_deny_automation_static_exceptions["Prod-alpha"],
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.tenant-self-iac-sa["Prod-alpha"].email}"
      ) &&
      length(local._tenant_iam_deny_policies["Prod-alpha"]["tenant-baseline-lockdown"].rules[3].exception_principals) == (
        length(local._tenant_deny_automation_static_exceptions["Prod-alpha"]) + 1
      )
    )
    error_message = "Expected all 4 rules consolidated in tenant-baseline-lockdown with tag-scoped sa_impersonation_lockdown."
  }
}

run "enabled_with_all_sub_toggles_false_creates_zero_policies" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  variables {
    iam_deny_guardrails = {
      enabled                       = true
      kms_iam_lockdown              = false
      kms_key_destruction           = false
      sa_impersonation_lockdown     = false
      tenant_gke_fleet_registration = false
    }
  }

  assert {
    condition = alltrue([
      for k, policies in local._tenant_iam_deny_policies : length(policies) == 0
    ])
    error_message = "Expected zero tenant IAM Deny policies when all rule sub-toggles are false."
  }
}

run "rejects_sa_impersonation_lockdown_without_tag" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  variables {
    iam_deny_guardrails = {
      enabled                   = true
      sa_impersonation_lockdown = true
    }
  }

  expect_failures = [
    var.iam_deny_guardrails,
  ]
}

run "rejects_non_v2_exception_principal" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  variables {
    iam_deny_guardrails = {
      enabled              = true
      exception_principals = ["group:breakglass@example.com"]
    }
  }

  expect_failures = [
    var.iam_deny_guardrails,
  ]
}

run "rejects_malformed_sa_impersonation_tag" {
  command = plan

  providers = {
    google              = google
    google-beta         = google-beta
    google.billing      = google.billing
    google-beta.billing = google-beta.billing
  }

  variables {
    iam_deny_guardrails = {
      enabled                   = true
      sa_impersonation_lockdown = true
      sa_impersonation_tag = {
        key   = "111111111111/scope' || true #"
        value = "platform"
      }
    }
  }

  expect_failures = [
    var.iam_deny_guardrails,
  ]
}
