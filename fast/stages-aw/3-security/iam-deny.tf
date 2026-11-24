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

# tfdoc:file:description Opt-in IAM v2 Deny lockdown for Access Context Manager.

locals {
  # Verified against https://cloud.google.com/iam/docs/deny-permissions-support.
  # Blocks all 19 supported Access Context Manager mutation and IAM permissions
  # while keeping read-only get and list permissions intact for auditing.
  _acm_denied_permissions = [
    "accesscontextmanager.googleapis.com/accessLevels.create",
    "accesscontextmanager.googleapis.com/accessLevels.delete",
    "accesscontextmanager.googleapis.com/accessLevels.replaceAll",
    "accesscontextmanager.googleapis.com/accessLevels.update",
    "accesscontextmanager.googleapis.com/authorizedOrgsDescs.create",
    "accesscontextmanager.googleapis.com/authorizedOrgsDescs.delete",
    "accesscontextmanager.googleapis.com/authorizedOrgsDescs.update",
    "accesscontextmanager.googleapis.com/gcpUserAccessBindings.create",
    "accesscontextmanager.googleapis.com/gcpUserAccessBindings.delete",
    "accesscontextmanager.googleapis.com/gcpUserAccessBindings.update",
    "accesscontextmanager.googleapis.com/policies.create",
    "accesscontextmanager.googleapis.com/policies.delete",
    "accesscontextmanager.googleapis.com/policies.setIamPolicy",
    "accesscontextmanager.googleapis.com/policies.update",
    "accesscontextmanager.googleapis.com/servicePerimeters.commit",
    "accesscontextmanager.googleapis.com/servicePerimeters.create",
    "accesscontextmanager.googleapis.com/servicePerimeters.delete",
    "accesscontextmanager.googleapis.com/servicePerimeters.replaceAll",
    "accesscontextmanager.googleapis.com/servicePerimeters.update",
  ]
  # Organization-level Access Context Manager policies reside under the
  # organization resource. Override parent with a folders/<id> attachment point
  # only when protecting folder-scoped access policies.
  _acm_deny_parent = coalesce(
    var.iam_deny_guardrails.parent,
    "organizations/${var.organization.id}"
  )
  _acm_deny_parent_encoded = urlencode(
    "cloudresourcemanager.googleapis.com/${local._acm_deny_parent}"
  )
  _acm_security_sa = try(
    coalesce(
      var.iam_deny_guardrails.security_service_account,
      try(var.service_accounts.security, null)
    ),
    null
  )
  _acm_exception_principals = distinct(concat(
    [
      for sa in compact([local._acm_security_sa]) :
      "principal://iam.googleapis.com/projects/-/serviceAccounts/${sa}"
    ],
    var.iam_deny_guardrails.exception_principals
  ))
}

resource "google_iam_deny_policy" "acm_lockdown" {
  count        = var.iam_deny_guardrails.enabled ? 1 : 0
  parent       = local._acm_deny_parent_encoded
  name         = "acm-vpc-sc-lockdown"
  display_name = "Restrict Access Context Manager mutations"
  rules {
    description = "Blocks unauthorized Access Context Manager changes."
    deny_rule {
      denied_principals    = ["principalSet://goog/public:all"]
      denied_permissions   = local._acm_denied_permissions
      exception_principals = local._acm_exception_principals
    }
  }
  depends_on = [module.vpc-sc]
}
