/**
 * Copyright 2026 Google LLC
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

# tfdoc:file:description Opt-in IAM v2 Deny lockdown for the NGFW bootstrap bucket.

locals {
  _ngfw_bootstrap_tag_key   = "ngfw-bootstrap"
  _ngfw_bootstrap_tag_value = "protected"
  _ngfw_bootstrap_project_tags = !var.iam_deny_guardrails.enabled ? {} : {
    (local._ngfw_bootstrap_tag_key) = {
      description = "Marks protected NGFW bootstrap buckets for IAM Deny lockdown."
      values = {
        (local._ngfw_bootstrap_tag_value) = {
          description = "NGFW bootstrap bucket protected by IAM Deny policy."
        }
      }
    }
  }
  _ngfw_bootstrap_tag_value_id = (
    !var.iam_deny_guardrails.enabled
    ? null
    : module.vdss-host-project.tag_values[
      "${local._ngfw_bootstrap_tag_key}/${local._ngfw_bootstrap_tag_value}"
    ].id
  )
  # Verified against https://cloud.google.com/iam/docs/deny-permissions-support.
  # Covers read, list, write, multipart upload, move, restore, retention,
  # folders, object contexts, delete, IAM, IP filter, managed folder, and
  # tag-binding mutation verbs.
  _ngfw_bootstrap_denied_permissions = [
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
  ]
  # Exempt only the NGFW compute SA, VDSS project service agents (needed by
  # Compute Engine to fetch bootstrap.xml at boot), Stage 2 automation SAs,
  # and explicit operator exception principals. Do not exempt all project SAs.
  _ngfw_bootstrap_static_exceptions = distinct(concat(
    [
      "principal://iam.googleapis.com/projects/-/serviceAccounts/${module.ngfw-service-account.email}",
    ],
    [
      for sa in compact([
        try(var.service_accounts.networking, null),
        try(var.service_accounts.networking-r, null),
      ]) : "principal://iam.googleapis.com/projects/-/serviceAccounts/${sa}"
    ],
    var.iam_deny_guardrails.exception_principals
  ))
  _ngfw_bootstrap_service_agent_set = (
    "principalSet://cloudresourcemanager.googleapis.com/projects/${module.vdss-host-project.number}/type/ServiceAgent"
  )
  _ngfw_bootstrap_exception_principals = concat(
    local._ngfw_bootstrap_static_exceptions,
    [local._ngfw_bootstrap_service_agent_set]
  )
  # IAM Deny denialCondition only supports resource tag CEL functions, not
  # resource.name matching.
  _ngfw_bootstrap_denial_expression = format(
    "resource.matchTag('%s/%s', '%s')",
    module.vdss-host-project.project_id,
    local._ngfw_bootstrap_tag_key,
    local._ngfw_bootstrap_tag_value
  )
  _ngfw_bootstrap_deny_policies = !var.iam_deny_guardrails.enabled ? {} : {
    ngfw-bootstrap-lockdown = {
      display_name = "Lock down NGFW bootstrap bucket"
      rules = [{
        description          = "Blocks unauthorized read, write, delete, IAM, and tag-removal operations on the tagged NGFW bootstrap bucket."
        denied_principals    = ["principalSet://goog/public:all"]
        denied_permissions   = local._ngfw_bootstrap_denied_permissions
        exception_principals = local._ngfw_bootstrap_exception_principals
        denial_condition = {
          title       = "tagged_ngfw_bootstrap_bucket"
          description = "Applies only to buckets tagged with ngfw-bootstrap=protected."
          expression  = local._ngfw_bootstrap_denial_expression
        }
      }]
    }
  }
  _ngfw_bootstrap_bucket_parents = {
    for k, _ in var.regions : k => (
      "//storage.googleapis.com/projects/_/buckets/${module.ngfw-bootstrap-bucket[k].name}"
    )
  }
  _ngfw_bootstrap_readonly_iam = (
    !var.iam_deny_guardrails.enabled ||
    !try(length(trimspace(var.service_accounts.networking-r)) > 0, false)
    ? {}
    : {
      "serviceAccount:${var.service_accounts.networking-r}" = [
        "roles/iam.denyReviewer",
        "roles/resourcemanager.tagViewer",
      ]
    }
  )
}

resource "terraform_data" "ngfw_bootstrap_bucket_ids" {
  for_each = var.iam_deny_guardrails.enabled ? var.regions : {}
  input    = module.ngfw-bootstrap-bucket[each.key].bucket.id
}

resource "google_tags_location_tag_binding" "ngfw_bootstrap_lockdown" {
  for_each   = var.iam_deny_guardrails.enabled ? var.regions : {}
  location   = lower(each.value)
  parent     = local._ngfw_bootstrap_bucket_parents[each.key]
  tag_value  = local._ngfw_bootstrap_tag_value_id
  depends_on = [module.ngfw-bootstrap-bucket]
  lifecycle {
    replace_triggered_by = [
      terraform_data.ngfw_bootstrap_bucket_ids[each.key],
    ]
  }
}

module "vdss-host-project-iam-deny" {
  source                  = "../../../modules/project"
  count                   = var.iam_deny_guardrails.enabled ? 1 : 0
  name                    = "net-vdss-host"
  prefix                  = var.prefix
  auto_create_network     = true
  default_service_account = "keep"
  project_reuse = {
    use_data_source = false
    attributes = {
      name   = module.vdss-host-project.name
      number = module.vdss-host-project.number
    }
  }
  service_agents_config = {
    create_primary_agents      = false
    grant_default_roles        = false
    grant_service_agent_editor = false
  }
  iam_by_principals_additive = local._ngfw_bootstrap_readonly_iam
  iam_deny_policies          = local._ngfw_bootstrap_deny_policies
  depends_on = [
    google_tags_location_tag_binding.ngfw_bootstrap_lockdown,
    google_storage_bucket_iam_binding.binding,
    google_storage_bucket_object.bootstrap_xml,
    google_storage_bucket_object.config_folders,
    google_storage_bucket_object.content_folders,
    google_storage_bucket_object.init_cfg,
    google_storage_bucket_object.license_folders,
    google_storage_bucket_object.software_folders,
  ]
}
