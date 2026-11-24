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

# tfdoc:file:description Lightweight tenant resources.


locals {
  _tenant_base_folder_iam = {
    for k, _ in local.tenant_envs : k => merge(
      {
        "roles/cloudasset.owner"               = [module.tenant-core-sa[k].iam_email]
        "roles/compute.xpnAdmin"               = [module.tenant-core-sa[k].iam_email]
        "roles/logging.admin"                  = [module.tenant-core-sa[k].iam_email]
        "roles/owner"                          = [module.tenant-core-sa[k].iam_email]
        "roles/resourcemanager.folderAdmin"    = [module.tenant-core-sa[k].iam_email]
        "roles/resourcemanager.projectCreator" = [module.tenant-core-sa[k].iam_email]
        "roles/resourcemanager.tagUser"        = [module.tenant-core-sa[k].iam_email]
        "roles/viewer"                         = local.tenant_iam[k]
      },
      !var.iam_deny_guardrails.enabled ? {} : {
        "roles/iam.denyReviewer" = [
          "serviceAccount:${var.automation.service_accounts.resman-r}",
        ]
      }
    )
  }
  _tenant_custom_folder_roles = distinct(concat(
    var.tenants_config.top_folder_roles,
    var.tenants_config.core_folder_roles,
    var.tenants_config.tenant_folder_roles
  ))
  _tenant_folder_iam = {
    for k, base in local._tenant_base_folder_iam : k => merge(
      {
        for role in local._tenant_custom_folder_roles :
        role => local.tenant_iam[k]
      },
      {
        for role, principals in base : role => distinct(concat(
          principals,
          contains(local._tenant_custom_folder_roles, role) ? local.tenant_iam[k] : []
        ))
      }
    )
  }
  tenant_iam = {
    for k, v in local.tenant_envs : k => [
      v.tenant_info.admin_principal,
      module.tenant-self-iac-sa[k].iam_email
    ]
  }
  gcs_locations = {
    for k, v in var.tenants :
    k => coalesce(try(v.locations.gcs, null), var.regions.primary)
  }
  tenant_envs = merge([for e, _ in var.envs_folders : {
    for t, v in var.tenants : "${e}-${t}" => {
      env         = e
      tenant      = t
      tenant_info = v
    }
    }
  ]...)
  # Verified against https://cloud.google.com/iam/docs/deny-permissions-support.
  _tenant_gke_fleet_denied_permissions = [
    "gkehub.googleapis.com/features.create",
    "gkehub.googleapis.com/features.delete",
    "gkehub.googleapis.com/features.setIamPolicy",
    "gkehub.googleapis.com/features.update",
    "gkehub.googleapis.com/fleet.create",
    "gkehub.googleapis.com/fleet.delete",
    "gkehub.googleapis.com/fleet.update",
    "gkehub.googleapis.com/gateway.delete",
    "gkehub.googleapis.com/gateway.patch",
    "gkehub.googleapis.com/gateway.post",
    "gkehub.googleapis.com/gateway.put",
    "gkehub.googleapis.com/membershipbindings.create",
    "gkehub.googleapis.com/membershipbindings.delete",
    "gkehub.googleapis.com/membershipbindings.update",
    "gkehub.googleapis.com/membershipfeatures.create",
    "gkehub.googleapis.com/membershipfeatures.delete",
    "gkehub.googleapis.com/membershipfeatures.update",
    "gkehub.googleapis.com/memberships.create",
    "gkehub.googleapis.com/memberships.delete",
    "gkehub.googleapis.com/memberships.generateConnectManifest",
    "gkehub.googleapis.com/memberships.setIamPolicy",
    "gkehub.googleapis.com/memberships.update",
    "gkehub.googleapis.com/namespaces.create",
    "gkehub.googleapis.com/namespaces.delete",
    "gkehub.googleapis.com/namespaces.update",
    "gkehub.googleapis.com/rbacrolebindings.create",
    "gkehub.googleapis.com/rbacrolebindings.delete",
    "gkehub.googleapis.com/rbacrolebindings.update",
    "gkehub.googleapis.com/scopes.create",
    "gkehub.googleapis.com/scopes.delete",
    "gkehub.googleapis.com/scopes.setIamPolicy",
    "gkehub.googleapis.com/scopes.update",
  ]
  # Irreversible destructive and key-disable KMS operations.
  _tenant_kms_destruction_denied_permissions = [
    "cloudkms.googleapis.com/cryptoKeyVersions.delete",
    "cloudkms.googleapis.com/cryptoKeyVersions.destroy",
    "cloudkms.googleapis.com/cryptoKeyVersions.update",
    "cloudkms.googleapis.com/cryptoKeys.delete",
    "cloudkms.googleapis.com/keyRings.delete",
  ]
  # KMS IAM and metadata updates split into a companion rule so environment
  # automation SAs can wire CMEK without gaining key-destruction authority.
  _tenant_kms_iam_denied_permissions = [
    "cloudkms.googleapis.com/cryptoKeys.setIamPolicy",
    "cloudkms.googleapis.com/cryptoKeys.update",
    "cloudkms.googleapis.com/keyRings.setIamPolicy",
  ]
  _tenant_sa_impersonation_denied_permissions = [
    "iam.googleapis.com/serviceAccountKeys.create",
    "iam.googleapis.com/serviceAccounts.actAs",
    "iam.googleapis.com/serviceAccounts.getAccessToken",
    "iam.googleapis.com/serviceAccounts.getOpenIdToken",
    "iam.googleapis.com/serviceAccounts.implicitDelegation",
    "iam.googleapis.com/serviceAccounts.setIamPolicy",
    "iam.googleapis.com/serviceAccounts.signBlob",
    "iam.googleapis.com/serviceAccounts.signJwt",
  ]
  _tenant_null_denial_condition = (
    true
    ? null
    : {
      title       = ""
      description = ""
      expression  = ""
    }
  )
  _tenant_sa_impersonation_condition = (
    var.iam_deny_guardrails.sa_impersonation_tag == null
    ? local._tenant_null_denial_condition
    : {
      title       = "tagged_sa_impersonation_scope"
      description = "Restricts service account impersonation on tagged resources."
      expression = format(
        "resource.matchTag('%s', '%s')",
        var.iam_deny_guardrails.sa_impersonation_tag.key,
        var.iam_deny_guardrails.sa_impersonation_tag.value
      )
    }
  )
  _tenant_deny_env_operator_exceptions = {
    for k, v in local.tenant_envs : k => distinct(concat(
      var.iam_deny_guardrails.exception_principals,
      lookup(var.iam_deny_guardrails.env_exception_principals, v.env, []),
      lookup(var.iam_deny_guardrails.env_exception_principals, lower(v.env), [])
    ))
  }
  _tenant_deny_base_exceptions = {
    for k, v in local.tenant_envs : k => distinct(concat(
      [
        for sa in compact([
          var.automation.service_accounts.resman,
          module.tenant-core-sa[k].email,
        ]) : "principal://iam.googleapis.com/projects/-/serviceAccounts/${sa}"
      ],
      local._tenant_deny_env_operator_exceptions[k]
    ))
  }
  # Map all non-prod environments (Dev, Int, Test, etc.) to *-dev-sa and Prod
  # strictly to *-prod-sa, matching Stage 1 automation SA conventions.
  _tenant_deny_gke_exceptions = {
    for k, v in local.tenant_envs : k => distinct(concat(
      local._tenant_deny_base_exceptions[k],
      [
        for sa in compact([
          lower(v.env) != "prod" ? try(module.branch-gke-dev-sa[0].email, null) : null,
          lower(v.env) == "prod" ? try(module.branch-gke-prod-sa[0].email, null) : null,
        ]) : "principal://iam.googleapis.com/projects/-/serviceAccounts/${sa}"
      ]
    ))
  }
  _tenant_deny_automation_static_exceptions = {
    for k, v in local.tenant_envs : k => distinct(concat(
      local._tenant_deny_base_exceptions[k],
      [
        for sa in compact([
          module.tenant-self-iac-sa[k].email,
          lower(v.env) != "prod" ? try(module.branch-dp-dev-sa[0].email, null) : null,
          lower(v.env) == "prod" ? try(module.branch-dp-prod-sa[0].email, null) : null,
          lower(v.env) != "prod" ? try(module.branch-gcve-dev-sa[0].email, null) : null,
          lower(v.env) == "prod" ? try(module.branch-gcve-prod-sa[0].email, null) : null,
          lower(v.env) != "prod" ? try(module.branch-gke-dev-sa[0].email, null) : null,
          lower(v.env) == "prod" ? try(module.branch-gke-prod-sa[0].email, null) : null,
          lower(v.env) != "prod" ? try(module.branch-pf-dev-sa[0].email, null) : null,
          lower(v.env) == "prod" ? try(module.branch-pf-prod-sa[0].email, null) : null,
        ]) : "principal://iam.googleapis.com/projects/-/serviceAccounts/${sa}"
      ]
    ))
  }
  _tenant_deny_service_agent_set = {
    for k, _ in local.tenant_envs : k => (
      "principalSet://cloudresourcemanager.googleapis.com/${module.tenant-top-folders[k].id}/type/ServiceAgent"
    )
  }
  _tenant_deny_automation_exceptions = {
    for k, _ in local.tenant_envs : k => concat(
      local._tenant_deny_automation_static_exceptions[k],
      [local._tenant_deny_service_agent_set[k]]
    )
  }
  _tenant_enabled_deny_rules = {
    for k, _ in local.tenant_envs : k => concat(
      !var.iam_deny_guardrails.kms_key_destruction ? [] : [{
        description          = "Blocks KMS key version destruction, disabling, and deletion."
        denied_principals    = tolist(["principalSet://goog/public:all"])
        denied_permissions   = tolist(local._tenant_kms_destruction_denied_permissions)
        denial_condition     = local._tenant_null_denial_condition
        exception_principals = tolist(local._tenant_deny_base_exceptions[k])
      }],
      !var.iam_deny_guardrails.kms_iam_lockdown ? [] : [{
        description          = "Restricts KMS key and keyring IAM and metadata updates to authorized automation."
        denied_principals    = tolist(["principalSet://goog/public:all"])
        denied_permissions   = tolist(local._tenant_kms_iam_denied_permissions)
        denial_condition     = local._tenant_null_denial_condition
        exception_principals = tolist(local._tenant_deny_automation_exceptions[k])
      }],
      !var.iam_deny_guardrails.tenant_gke_fleet_registration ? [] : [{
        description          = "Blocks GKE Hub fleet and membership mutations in tenant folders."
        denied_principals    = tolist(["principalSet://goog/public:all"])
        denied_permissions   = tolist(local._tenant_gke_fleet_denied_permissions)
        denial_condition     = local._tenant_null_denial_condition
        exception_principals = tolist(local._tenant_deny_gke_exceptions[k])
      }],
      !var.iam_deny_guardrails.sa_impersonation_lockdown ? [] : [{
        description          = "Blocks service account actAs, token minting, key creation, and IAM changes."
        denied_principals    = tolist(["principalSet://goog/public:all"])
        denied_permissions   = tolist(local._tenant_sa_impersonation_denied_permissions)
        denial_condition     = local._tenant_sa_impersonation_condition
        exception_principals = tolist(local._tenant_deny_automation_exceptions[k])
      }]
    )
  }
  _tenant_iam_deny_policies = {
    for k, rules in local._tenant_enabled_deny_rules : k => (
      !var.iam_deny_guardrails.enabled || length(rules) == 0
      ? {}
      : {
        tenant-baseline-lockdown = {
          display_name = "Tenant folder IAM Deny baseline guardrails"
          rules        = rules
        }
      }
    )
  }
}

# Tenant folders (top, core, self)
module "tenant-top-folders" {
  source   = "../../../modules/folder"
  for_each = local.tenant_envs
  parent   = module.branch-envs-folders[each.value.env].id
  name     = "Project ${each.value.tenant} ${each.value.env}"
  iam_by_principals = contains(local._tenant_custom_folder_roles, "roles/browser") ? {} : {
    (each.value.tenant_info.admin_principal) = ["roles/browser"]
  }
}

module "tenant-top-folders-iam" {
  source            = "../../../modules/folder"
  for_each          = local.tenant_envs
  id                = module.tenant-top-folders[each.key].id
  folder_create     = false
  tag_bindings      = null
  iam               = local._tenant_folder_iam[each.key]
  iam_deny_policies = local._tenant_iam_deny_policies[each.key]
}

removed {
  from = module.tenant-core-folders-iam
  lifecycle {
    destroy = false
  }
}

removed {
  from = module.tenant-self-folders-iam
  lifecycle {
    destroy = false
  }
}

# Tenant IaC resources (core)

module "tenant-core-sa" {
  source      = "../../../modules/iam-service-account"
  for_each    = local.tenant_envs
  project_id  = var.automation.project_id
  name        = lower("tn-${each.key}-prod-0")
  description = "Terraform service account for tenant ${each.key}."
  prefix      = var.prefix
  iam_project_roles = {
    (var.automation.project_id) = ["roles/serviceusage.serviceUsageConsumer"]
  }
}

module "tenant-core-gcs" {
  source        = "../../../modules/gcs"
  for_each      = local.tenant_envs
  project_id    = var.automation.project_id
  name          = lower("tn-${each.key}-0")
  prefix        = var.prefix
  versioning    = true
  force_destroy = var.force_destroy
  location      = local.gcs_locations[each.value.tenant]
  storage_class = (
    length(split("-", local.gcs_locations[each.value.tenant])) < 2
    ? "MULTI_REGIONAL"
    : "REGIONAL"
  )
  encryption_key = module.tenant-project-keys[each.key].key_ids["gcs"]
  depends_on     = [module.tenant-project-keys, google_kms_crypto_key_iam_member.tenant_kms]
  iam = {
    "roles/storage.objectAdmin" = [module.tenant-core-sa[each.key].iam_email]
  }
}

# Tenant IaC project and resources (self)
module "tenant-self-iac-projects" {
  source   = "../../../modules/project"
  for_each = local.tenant_envs
  providers = {
    google      = google.billing
    google-beta = google-beta.billing
  }
  billing_account = (
    each.value.tenant_info.billing_account != null
    ? each.value.tenant_info.billing_account
    : var.billing_account.id
  )
  name   = lower("${each.key}-iac-core-0")
  parent = module.tenant-top-folders[each.key].id
  prefix = var.prefix
  factories_config = {
    org_policies = "${var.factories_config.org_policies}/${lower("${each.key}-iac-core-0")}"
  }
  iam_by_principals = {
    (each.value.tenant_info.admin_principal) = [
      "roles/iam.serviceAccountAdmin",
      "roles/iam.serviceAccountTokenCreator",
      "roles/iam.workloadIdentityPoolAdmin"
    ]
  }
  iam = {
    # Expected that the service account will have owner permissions on the project it
    # creates this role will be removed during stage 3 when sa-lockdown-runs.
    # This iam simply reaffirms the permissions resman should already have.
    "roles/owner" = [
      "serviceAccount:${var.automation.service_accounts.resman}"
    ]
    (local.custom_roles.storage_viewer) = [
      "serviceAccount:${var.automation.service_accounts.resman-r}"
    ]
    "roles/viewer" = [
      "serviceAccount:${var.automation.service_accounts.resman-r}"
    ]
  }
  services = [
    "accesscontextmanager.googleapis.com",
    "bigquery.googleapis.com",
    "bigqueryreservation.googleapis.com",
    "bigquerystorage.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "container.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "essentialcontacts.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "orgpolicy.googleapis.com",
    "pubsub.googleapis.com",
    "servicenetworking.googleapis.com",
    "serviceusage.googleapis.com",
    "stackdriver.googleapis.com",
    "storage-component.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com"
  ]
}

module "tenant-self-iac-gcs-outputs" {
  source     = "../../../modules/gcs"
  for_each   = local.tenant_envs
  project_id = module.tenant-self-iac-projects[each.key].project_id
  location   = local.gcs_locations[each.value.tenant]
  storage_class = (
    length(split("-", local.gcs_locations[each.value.tenant])) < 2
    ? "MULTI_REGIONAL"
    : "REGIONAL"
  )
  name          = "${each.key}-iac-outputs-0"
  prefix        = var.prefix
  versioning    = true
  force_destroy = var.force_destroy
  iam = {
    "roles/storage.objectAdmin" = [module.tenant-core-sa[each.key].iam_email]
  }
  encryption_key = module.tenant-project-keys[each.key].key_ids["gcs"]
  depends_on     = [module.tenant-project-keys, google_kms_crypto_key_iam_member.tenant_kms]

}

module "tenant-self-iac-gcs-states" {
  source     = "../../../modules/gcs"
  for_each   = local.tenant_envs
  project_id = module.tenant-self-iac-projects[each.key].project_id
  location   = local.gcs_locations[each.value.tenant]
  storage_class = (
    length(split("-", local.gcs_locations[each.value.tenant])) < 2
    ? "MULTI_REGIONAL"
    : "REGIONAL"
  )
  name           = "${each.key}-iac-0"
  prefix         = var.prefix
  versioning     = true
  force_destroy  = var.force_destroy
  encryption_key = module.tenant-project-keys[each.key].key_ids["gcs"]
  depends_on     = [module.tenant-project-keys, google_kms_crypto_key_iam_member.tenant_kms]
}

module "tenant-self-iac-sa" {
  source      = "../../../modules/iam-service-account"
  for_each    = local.tenant_envs
  project_id  = module.tenant-self-iac-projects[each.key].project_id
  name        = lower("${each.key}-iac-0")
  description = "Terraform automation service account."
  prefix      = var.prefix
  iam_storage_roles = {
    (module.tenant-self-iac-gcs-outputs[each.key].name) = [
      "roles/storage.admin"
    ]
    (module.tenant-self-iac-gcs-states[each.key].name) = [
      "roles/storage.admin"
    ]
  }
}

# Tenant main project and resources (self)
module "tenant-self-main-projects" {
  source   = "../../../modules/project"
  for_each = local.tenant_envs
  providers = {
    google      = google.billing
    google-beta = google-beta.billing
  }
  billing_account = (
    each.value.tenant_info.billing_account != null
    ? each.value.tenant_info.billing_account
    : var.billing_account.id
  )
  name   = lower("${each.key}-main-0")
  parent = module.tenant-top-folders[each.key].id
  prefix = var.prefix
  factories_config = {
    org_policies = "${var.factories_config.org_policies}/${lower("${each.key}-main-0")}"
  }
  iam_by_principals = {
    (each.value.tenant_info.admin_principal) = [
      "roles/iam.serviceAccountAdmin",
      "roles/iam.serviceAccountTokenCreator",
      "roles/iam.workloadIdentityPoolAdmin"
    ]
  }
  iam = {
    # Expected that the service account will have owner permissions on the project it
    # creates this role will be removed during stage 3 when sa-lockdown-runs.
    # This iam simply reaffirms the permissions resman should already have.
    "roles/owner" = [
      "serviceAccount:${var.automation.service_accounts.resman}"
    ]
    (local.custom_roles.storage_viewer) = [
      "serviceAccount:${var.automation.service_accounts.resman-r}"
    ]
    "roles/viewer" = [
      "serviceAccount:${var.automation.service_accounts.resman-r}"
    ]
  }
  compute_metadata = {
    google-compute-default-region = var.regions.primary
    google-compute-default-zone   = "${var.regions.primary}-b" # There always seems to be a -b zone
  }
  services = [
    "accesscontextmanager.googleapis.com",
    "bigquery.googleapis.com",
    "bigqueryreservation.googleapis.com",
    "bigquerystorage.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "container.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "essentialcontacts.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "orgpolicy.googleapis.com",
    "pubsub.googleapis.com",
    "servicenetworking.googleapis.com",
    "serviceusage.googleapis.com",
    "stackdriver.googleapis.com",
    "storage-component.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com"
  ]
}

#added for key and bucket provisioning
resource "time_sleep" "tenant_project_iam_propagation_delay" {
  create_duration = "30s"

  depends_on = [
    module.tenant-self-iac-projects,
    module.tenant-self-main-projects
  ]
}

