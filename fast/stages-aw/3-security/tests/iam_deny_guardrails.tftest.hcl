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

mock_provider "google" {
  alias = "billing"
}

mock_provider "google-beta" {}

mock_provider "google-beta" {
  alias = "billing"
}

mock_provider "local" {}
mock_provider "time" {}

variables {
  alert_email = "alerts@example.com"
  assured_workloads = {
    regime   = "IL5"
    location = "us"
    folder   = "folders/123456789012"
  }
  automation = {
    outputs_bucket = "test-outputs-bucket"
  }
  billing_account = {
    id = "000000-AAAAAA-000000"
  }
  common_services_folder = "folders/123456789012"
  envs_folders = {
    Prod = { admin = "group:prod-admins@example.com" }
  }
  folder_ids = {
    security = "folders/123456789012"
  }
  organization = {
    domain      = "example.com"
    id          = 123456789012
    customer_id = "C00000000"
  }
  prefix = "test"
  regions = {
    primary = "us-east4"
  }
  service_accounts = {
    data-platform-dev    = "dp-dev@test-automation.iam.gserviceaccount.com"
    data-platform-prod   = "dp-prod@test-automation.iam.gserviceaccount.com"
    gke-dev              = "gke-dev@test-automation.iam.gserviceaccount.com"
    gke-prod             = "gke-prod@test-automation.iam.gserviceaccount.com"
    project-factory-dev  = "pf-dev@test-automation.iam.gserviceaccount.com"
    project-factory-prod = "pf-prod@test-automation.iam.gserviceaccount.com"
  }
  tenant_accounts = {}
}

run "disabled_by_default" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    local               = local
    time                = time
  }

  assert {
    condition     = length(google_iam_deny_policy.acm_lockdown) == 0
    error_message = "Expected zero ACM IAM Deny policies when iam_deny_guardrails.enabled is false."
  }
}

run "enabled_defaults_to_organization_parent" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    local               = local
    time                = time
  }

  variables {
    iam_deny_guardrails = {
      enabled                  = true
      security_service_account = "sec@test-automation.iam.gserviceaccount.com"
      exception_principals = [
        "principalSet://goog/group/gcp-security-admins@example.com",
      ]
    }
  }

  assert {
    condition = (
      length(google_iam_deny_policy.acm_lockdown) == 1 &&
      google_iam_deny_policy.acm_lockdown[0].name == "acm-vpc-sc-lockdown" &&
      google_iam_deny_policy.acm_lockdown[0].parent == urlencode("cloudresourcemanager.googleapis.com/organizations/123456789012")
    )
    error_message = "Expected ACM IAM Deny policy attached to organizations/123456789012 by default."
  }

  assert {
    condition = (
      length(google_iam_deny_policy.acm_lockdown[0].rules[0].deny_rule[0].denied_permissions) == 19 &&
      contains(
        google_iam_deny_policy.acm_lockdown[0].rules[0].deny_rule[0].denied_permissions,
        "accesscontextmanager.googleapis.com/servicePerimeters.commit"
      ) &&
      contains(
        google_iam_deny_policy.acm_lockdown[0].rules[0].deny_rule[0].denied_permissions,
        "accesscontextmanager.googleapis.com/policies.setIamPolicy"
      ) &&
      contains(
        google_iam_deny_policy.acm_lockdown[0].rules[0].deny_rule[0].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/sec@test-automation.iam.gserviceaccount.com"
      ) &&
      contains(
        google_iam_deny_policy.acm_lockdown[0].rules[0].deny_rule[0].exception_principals,
        "principalSet://goog/group/gcp-security-admins@example.com"
      )
    )
    error_message = "Expected all 19 verified ACM mutation permissions and formatted exception principals."
  }
}

run "enabled_supports_folder_parent_override" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    local               = local
    time                = time
  }

  variables {
    iam_deny_guardrails = {
      enabled = true
      parent  = "folders/999999999999"
      exception_principals = [
        "principalSet://goog/group/gcp-security-admins@example.com",
      ]
    }
  }

  assert {
    condition = (
      length(google_iam_deny_policy.acm_lockdown) == 1 &&
      google_iam_deny_policy.acm_lockdown[0].parent == urlencode("cloudresourcemanager.googleapis.com/folders/999999999999")
    )
    error_message = "Expected folder parent override to take effect on ACM IAM Deny policy."
  }
}

run "enabled_auto_exempts_service_accounts_security" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    local               = local
    time                = time
  }

  variables {
    service_accounts = {
      data-platform-dev    = "dp-dev@test-automation.iam.gserviceaccount.com"
      data-platform-prod   = "dp-prod@test-automation.iam.gserviceaccount.com"
      gke-dev              = "gke-dev@test-automation.iam.gserviceaccount.com"
      gke-prod             = "gke-prod@test-automation.iam.gserviceaccount.com"
      project-factory-dev  = "pf-dev@test-automation.iam.gserviceaccount.com"
      project-factory-prod = "pf-prod@test-automation.iam.gserviceaccount.com"
      security             = "sec-stage1@test-automation.iam.gserviceaccount.com"
      security-r           = "sec-stage1-r@test-automation.iam.gserviceaccount.com"
    }
    iam_deny_guardrails = {
      enabled = true
    }
  }

  assert {
    condition = (
      length(google_iam_deny_policy.acm_lockdown) == 1 &&
      toset(google_iam_deny_policy.acm_lockdown[0].rules[0].deny_rule[0].exception_principals) == toset([
        "principal://iam.googleapis.com/projects/-/serviceAccounts/sec-stage1@test-automation.iam.gserviceaccount.com",
      ])
    )
    error_message = "Expected service_accounts.security to auto-exempt Stage 3 automation SA when enabled."
  }
}

run "rejects_empty_exception_principals_when_enabled" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    local               = local
    time                = time
  }

  variables {
    iam_deny_guardrails = {
      enabled              = true
      exception_principals = []
    }
  }

  expect_failures = [
    var.iam_deny_guardrails,
  ]
}

run "rejects_invalid_parent_format" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    local               = local
    time                = time
  }

  variables {
    iam_deny_guardrails = {
      enabled = true
      parent  = "projects/123456789012"
      exception_principals = [
        "principalSet://goog/group/gcp-security-admins@example.com",
      ]
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
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    local               = local
    time                = time
  }

  variables {
    iam_deny_guardrails = {
      enabled              = true
      exception_principals = ["group:gcp-security-admins@example.com"]
    }
  }

  expect_failures = [
    var.iam_deny_guardrails,
  ]
}
