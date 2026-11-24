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

# tfdoc:file:description Central Cloud Monitoring scoping project.

locals {
  _monitoring_core_projects = (
    try(var.monitoring_project.scope_core_projects, false)
    ? compact([
      module.automation-project.project_id,
      module.log-export-project.project_id,
      (
        local.billing_mode == "org"
        ? module.billing-export-project[0].project_id
        : ""
      )
    ])
    : []
  )
  _monitoring_deletion_policy = (
    var.monitoring_project == null
    ? null
    : coalesce(
      var.monitoring_project.deletion_policy,
      var.project_deletion_policies.monitoring
    )
  )
  _monitoring_parent = (
    var.monitoring_project == null
    ? null
    : coalesce(
      var.monitoring_project.parent_id,
      var.project_parent_ids.monitoring,
      module.branch-common-services-folder.folder.name
    )
  )
  _monitoring_self_id = try(module.monitoring-project[0].project_id, "")
  monitoring_monitored_projects = (
    var.monitoring_project == null
    ? toset([])
    : toset([
      for p in distinct(concat(
        local._monitoring_core_projects,
        (
          var.monitoring_project.monitored_projects == null
          ? []
          : var.monitoring_project.monitored_projects
        )
      )) : p if p != local._monitoring_self_id
    ])
  )
}

module "monitoring-project" {
  source                  = "../../../modules/project"
  count                   = var.monitoring_project != null ? 1 : 0
  billing_account         = var.billing_account.id
  default_service_account = "deprivilege"
  name = coalesce(
    var.monitoring_project.name, "monitoring-0"
  )
  deletion_policy = local._monitoring_deletion_policy
  lien_reason     = "Protected by default as a core project."
  parent          = local._monitoring_parent
  prefix          = local.prefix
  contacts = (
    var.bootstrap_user != null ? {} : local.essential_contacts
  )
  iam = {
    "roles/owner" = compact([
      module.automation-tf-bootstrap-sa.iam_email,
      var.bootstrap_user != null ? "user:${var.bootstrap_user}" : null
    ])
    "roles/viewer" = [module.automation-tf-bootstrap-r-sa.iam_email]
  }
  services = [
    "monitoring.googleapis.com",
    "logging.googleapis.com",
  ]
  depends_on = [module.organization-logging]
}

resource "google_monitoring_monitored_project" "default" {
  for_each      = local.monitoring_monitored_projects
  metrics_scope = module.monitoring-project[0].project_id
  name          = each.key
  depends_on    = [module.monitoring-project]
}
