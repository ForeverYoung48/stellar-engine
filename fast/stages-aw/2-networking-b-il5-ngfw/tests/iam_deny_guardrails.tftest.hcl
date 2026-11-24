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

mock_provider "external" {}

mock_provider "tls" {}

mock_provider "random" {}

mock_provider "time" {}

mock_provider "local" {}

mock_provider "null" {}

variables {
  alert_email = "admin@example.com"
  automation = {
    outputs_bucket = "test-outputs-bucket"
  }
  billing_account = {
    id = "000000-AAAAAA-000000"
  }
  cidrs = {
    healthchecks = ["35.191.0.0/16"]
    iap          = ["35.235.240.0/20"]
  }
  envs_folders = {
    Prod = { admin = "group:prod-admins@example.com" }
    Int  = { admin = "group:int-admins@example.com" }
  }
  folder_ids = {
    networking = "folders/123456789012"
  }
  organization = {
    domain      = "example.com"
    id          = 123456789012
    customer_id = "C00000000"
  }
  prefix = "test"
  proxy_subnets = {
    Prod = "10.1.1.0/24"
    Int  = "10.1.2.0/24"
  }
  regions = {
    primary = "us-east4"
  }
  subnets = {
    landing = [
      {
        name          = "landing-default"
        ip_cidr_range = "10.64.0.0/24"
        region        = "us-east4"
      },
    ]
    dmz = [
      {
        name          = "dmz-default"
        ip_cidr_range = "10.64.128.0/24"
        region        = "us-east4"
      },
    ]
    mgmt = [
      {
        name          = "mgmt-default"
        ip_cidr_range = "10.64.129.0/24"
        region        = "us-east4"
      },
    ]
    prod = [
      {
        name          = "prod-tenant-1-subnet"
        ip_cidr_range = "10.201.0.0/16"
        region        = "us-east4"
        tenant        = "ten-1"
      },
    ]
    int = [
      {
        name          = "int-tenant-1-subnet"
        ip_cidr_range = "10.150.0.0/16"
        region        = "us-east4"
        tenant        = "ten-1"
      },
    ]
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
    external            = external
    tls                 = tls
    random              = random
    time                = time
    local               = local
    null                = null
  }

  assert {
    condition = (
      length(module.vdss-host-project-iam-deny) == 0 &&
      length(local._ngfw_bootstrap_deny_policies) == 0 &&
      length(local._ngfw_bootstrap_readonly_iam) == 0
    )
    error_message = "Expected zero google_iam_deny_policy resources when iam_deny_guardrails.enabled is false."
  }

  assert {
    condition = (
      length(module.vdss-host-project.tag_keys) == 0 &&
      length(module.vdss-host-project.tag_values) == 0 &&
      length(google_tags_location_tag_binding.ngfw_bootstrap_lockdown) == 0 &&
      length(terraform_data.ngfw_bootstrap_bucket_ids) == 0
    )
    error_message = "Expected zero tag keys, tag values, and regional tag bindings when iam_deny_guardrails.enabled is false."
  }
}

run "enabled_with_networking_service_accounts" {
  command = plan

  override_resource {
    target          = module.vdss-host-project.google_project.project[0]
    override_during = plan
    values = {
      number = "111222333444"
    }
  }

  override_resource {
    target          = module.vdss-host-project.google_tags_tag_value.default["ngfw-bootstrap/protected"]
    override_during = plan
    values = {
      id = "tagValues/281474976710657"
    }
  }

  override_resource {
    target          = module.ngfw-bootstrap-bucket["primary"].google_storage_bucket.bucket[0]
    override_during = plan
    values = {
      id = "test-net-vdss-host-ngfw-bootstrap-primary"
    }
  }

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    external            = external
    tls                 = tls
    random              = random
    time                = time
    local               = local
    null                = null
  }

  variables {
    iam_deny_guardrails = {
      enabled = true
      exception_principals = [
        "principalSet://goog/group/breakglass@example.com",
      ]
    }
    service_accounts = {
      data-platform-dev    = "dp-dev@test-automation.iam.gserviceaccount.com"
      data-platform-prod   = "dp-prod@test-automation.iam.gserviceaccount.com"
      gke-dev              = "gke-dev@test-automation.iam.gserviceaccount.com"
      gke-prod             = "gke-prod@test-automation.iam.gserviceaccount.com"
      networking           = "net@test-automation.iam.gserviceaccount.com"
      networking-r         = "net-r@test-automation.iam.gserviceaccount.com"
      project-factory-dev  = "pf-dev@test-automation.iam.gserviceaccount.com"
      project-factory-prod = "pf-prod@test-automation.iam.gserviceaccount.com"
    }
  }

  assert {
    condition = (
      module.vdss-host-project.tag_keys["ngfw-bootstrap"].short_name == "ngfw-bootstrap" &&
      module.vdss-host-project.tag_values["ngfw-bootstrap/protected"].short_name == "protected"
    )
    error_message = "Expected VDSS host project tag key ngfw-bootstrap and tag value protected."
  }

  assert {
    condition = (
      length(google_tags_location_tag_binding.ngfw_bootstrap_lockdown) == 1 &&
      google_tags_location_tag_binding.ngfw_bootstrap_lockdown["primary"].location == "us-east4" &&
      google_tags_location_tag_binding.ngfw_bootstrap_lockdown["primary"].tag_value == "tagValues/281474976710657" &&
      google_tags_location_tag_binding.ngfw_bootstrap_lockdown["primary"].parent == "//storage.googleapis.com/projects/_/buckets/${module.ngfw-bootstrap-bucket["primary"].name}" &&
      terraform_data.ngfw_bootstrap_bucket_ids["primary"].input == "test-net-vdss-host-ngfw-bootstrap-primary"
    )
    error_message = "Expected lowercase regional tag bindings wired to replace_triggered_by bucket ID trackers."
  }

  assert {
    condition = (
      length(module.vdss-host-project-iam-deny) == 1 &&
      toset(keys(local._ngfw_bootstrap_deny_policies)) == toset(["ngfw-bootstrap-lockdown"]) &&
      toset(local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].denied_principals) == toset(["principalSet://goog/public:all"]) &&
      local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].denial_condition.expression == "resource.matchTag('${module.vdss-host-project.project_id}/ngfw-bootstrap', 'protected')" &&
      length(local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].denied_permissions) == 34 &&
      toset(local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].denied_permissions) == toset([
        "storage.googleapis.com/buckets.createTagBinding",
        "storage.googleapis.com/buckets.delete",
        "storage.googleapis.com/buckets.deleteTagBinding",
        "storage.googleapis.com/buckets.enableObjectRetention",
        "storage.googleapis.com/buckets.get",
        "storage.googleapis.com/buckets.getIamPolicy",
        "storage.googleapis.com/buckets.relocate",
        "storage.googleapis.com/buckets.restore",
        "storage.googleapis.com/buckets.setIamPolicy",
        "storage.googleapis.com/buckets.setIpFilter",
        "storage.googleapis.com/buckets.update",
        "storage.googleapis.com/folders.create",
        "storage.googleapis.com/folders.delete",
        "storage.googleapis.com/folders.rename",
        "storage.googleapis.com/managedFolders.create",
        "storage.googleapis.com/managedFolders.delete",
        "storage.googleapis.com/managedFolders.setIamPolicy",
        "storage.googleapis.com/managedFolders.update",
        "storage.googleapis.com/multipartUploads.abort",
        "storage.googleapis.com/multipartUploads.create",
        "storage.googleapis.com/objects.create",
        "storage.googleapis.com/objects.createContext",
        "storage.googleapis.com/objects.delete",
        "storage.googleapis.com/objects.deleteContext",
        "storage.googleapis.com/objects.get",
        "storage.googleapis.com/objects.getIamPolicy",
        "storage.googleapis.com/objects.list",
        "storage.googleapis.com/objects.move",
        "storage.googleapis.com/objects.overrideUnlockedRetention",
        "storage.googleapis.com/objects.restore",
        "storage.googleapis.com/objects.setIamPolicy",
        "storage.googleapis.com/objects.setRetention",
        "storage.googleapis.com/objects.update",
        "storage.googleapis.com/objects.updateContext",
      ])
    )
    error_message = "Expected google_iam_deny_policy blocking all 34 verified storage permissions on tagged bootstrap buckets."
  }

  assert {
    condition = (
      contains(
        local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.ngfw-service-account.email}"
      ) &&
      contains(
        local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].exception_principals,
        "principalSet://cloudresourcemanager.googleapis.com/projects/111222333444/type/ServiceAgent"
      ) &&
      contains(
        local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/net@test-automation.iam.gserviceaccount.com"
      ) &&
      contains(
        local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/net-r@test-automation.iam.gserviceaccount.com"
      ) &&
      contains(
        local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].exception_principals,
        "principalSet://goog/group/breakglass@example.com"
      ) &&
      !contains(
        local._ngfw_bootstrap_deny_policies["ngfw-bootstrap-lockdown"].rules[0].exception_principals,
        "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.bastion-service-account.email}"
      ) &&
      local._ngfw_bootstrap_readonly_iam["serviceAccount:net-r@test-automation.iam.gserviceaccount.com"] == [
        "roles/iam.denyReviewer",
        "roles/resourcemanager.tagViewer",
      ]
    )
    error_message = "Expected bootstrap deny policy to exempt NGFW SA, VDSS ServiceAgent set, networking SAs, and operator exceptions only, and bind read-only reviewer roles for networking-r."
  }
}

run "rejects_enabled_without_networking_sa_or_exceptions" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    external            = external
    tls                 = tls
    random              = random
    time                = time
    local               = local
    null                = null
  }

  variables {
    iam_deny_guardrails = {
      enabled = true
    }
    service_accounts = null
  }

  expect_failures = [
    var.iam_deny_guardrails,
  ]
}

run "rejects_invalid_v1_exception_principal" {
  command = plan

  providers = {
    google              = google
    google.billing      = google.billing
    google-beta         = google-beta
    google-beta.billing = google-beta.billing
    external            = external
    tls                 = tls
    random              = random
    time                = time
    local               = local
    null                = null
  }

  variables {
    iam_deny_guardrails = {
      enabled = true
      exception_principals = [
        "group:net-admins@example.com",
      ]
    }
  }

  expect_failures = [
    var.iam_deny_guardrails,
  ]
}
