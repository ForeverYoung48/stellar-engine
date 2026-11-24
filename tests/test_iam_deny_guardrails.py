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

"""Checks opt-in IAM v2 Deny baseline guardrails across Stages 1, 2b, and 3."""

import pathlib
import re
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_STAGE1_DIR = _REPO_ROOT / "fast/stages-aw/1-resman"
_STAGE2B_DIR = _REPO_ROOT / "fast/stages-aw/2-networking-b-il5-ngfw"
_STAGE3_DIR = _REPO_ROOT / "fast/stages-aw/3-security"

# Verified against https://cloud.google.com/iam/docs/deny-permissions-support.
_VERIFIED_DENY_PERMISSIONS = frozenset(
    {
        # Access Context Manager mutations (19)
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
        # Cloud KMS destruction, disabling, update, and IAM (8)
        "cloudkms.googleapis.com/cryptoKeyVersions.delete",
        "cloudkms.googleapis.com/cryptoKeyVersions.destroy",
        "cloudkms.googleapis.com/cryptoKeyVersions.update",
        "cloudkms.googleapis.com/cryptoKeys.delete",
        "cloudkms.googleapis.com/cryptoKeys.setIamPolicy",
        "cloudkms.googleapis.com/cryptoKeys.update",
        "cloudkms.googleapis.com/keyRings.delete",
        "cloudkms.googleapis.com/keyRings.setIamPolicy",
        # GKE Hub fleet, membership, namespace, RBAC, and gateway mutations (32)
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
        # IAM service account impersonation, actAs, keys, and IAM (8)
        "iam.googleapis.com/serviceAccountKeys.create",
        "iam.googleapis.com/serviceAccounts.actAs",
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccounts.getOpenIdToken",
        "iam.googleapis.com/serviceAccounts.implicitDelegation",
        "iam.googleapis.com/serviceAccounts.setIamPolicy",
        "iam.googleapis.com/serviceAccounts.signBlob",
        "iam.googleapis.com/serviceAccounts.signJwt",
        # Cloud Storage read, write, folders, contexts, delete, IAM, tags (34)
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
    }
)

_PERM_RE = re.compile(r'"([a-z0-9-]+\.googleapis\.com/[a-zA-Z0-9_.*]+)"')


def _extract_variable_block(stage_dir, var_name):
    """Returns the HCL block for a variable declaration."""
    text = (stage_dir / "variables.tf").read_text(encoding="utf-8")
    match = re.search(
        rf'variable "{re.escape(var_name)}" \{{[\s\S]*?\n\}}', text
    )
    assert match is not None, f"variable {var_name} not found in {stage_dir}"
    return match.group(0)


def _extract_list_permissions(tf_text, local_name):
    """Returns all quoted IAM v2 permission strings in a local list."""
    match = re.search(
        rf"{re.escape(local_name)}\s*=\s*\[([\s\S]*?)\]",
        tf_text,
    )
    assert match is not None, f"local {local_name} not found"
    return _PERM_RE.findall(match.group(1))


class TestIamDenyGuardrails(unittest.TestCase):
    def test_all_stages_default_enabled_to_false(self):
        for stage_dir in (_STAGE1_DIR, _STAGE2B_DIR, _STAGE3_DIR):
            with self.subTest(stage=stage_dir.name):
                block = _extract_variable_block(
                    stage_dir, "iam_deny_guardrails"
                )
                self.assertRegex(
                    block,
                    r"\n\s*enabled\s*=\s*optional\(bool,\s*false\)\n",
                )
                self.assertIn("default  = {}", block)
                self.assertIn("nullable = false", block)

    def test_all_denied_permissions_are_vendor_verified(self):
        stage1_tf = (_STAGE1_DIR / "branch-tenants.tf").read_text(
            encoding="utf-8"
        )
        stage2b_tf = (_STAGE2B_DIR / "iam-deny.tf").read_text(encoding="utf-8")
        stage3_tf = (_STAGE3_DIR / "iam-deny.tf").read_text(encoding="utf-8")

        lists = [
            (
                "1-resman-gkehub",
                _extract_list_permissions(
                    stage1_tf, "_tenant_gke_fleet_denied_permissions"
                ),
            ),
            (
                "1-resman-kms-destroy",
                _extract_list_permissions(
                    stage1_tf, "_tenant_kms_destruction_denied_permissions"
                ),
            ),
            (
                "1-resman-kms-iam",
                _extract_list_permissions(
                    stage1_tf, "_tenant_kms_iam_denied_permissions"
                ),
            ),
            (
                "1-resman-sa-impersonation",
                _extract_list_permissions(
                    stage1_tf, "_tenant_sa_impersonation_denied_permissions"
                ),
            ),
            (
                "2-networking-b-il5-ngfw",
                _extract_list_permissions(
                    stage2b_tf, "_ngfw_bootstrap_denied_permissions"
                ),
            ),
            (
                "3-security",
                _extract_list_permissions(stage3_tf, "_acm_denied_permissions"),
            ),
        ]

        seen = set()
        for stage_name, perms in lists:
            with self.subTest(stage=stage_name, count=len(perms)):
                self.assertGreater(len(perms), 0)
                self.assertEqual(len(perms), len(set(perms)))
                unknown = sorted(set(perms) - _VERIFIED_DENY_PERMISSIONS)
                self.assertEqual(
                    unknown,
                    [],
                    f"Unverified IAM Deny permissions in {stage_name}: "
                    f"{unknown}",
                )
                seen.update(perms)

        self.assertEqual(seen, _VERIFIED_DENY_PERMISSIONS)

    def test_stage1_wires_native_folder_module_and_safe_defaults(self):
        tf_text = (_STAGE1_DIR / "branch-tenants.tf").read_text(
            encoding="utf-8"
        )
        net_tf_text = (_STAGE1_DIR / "branch-networking.tf").read_text(
            encoding="utf-8"
        )
        vars_block = _extract_variable_block(_STAGE1_DIR, "iam_deny_guardrails")

        self.assertIn(
            "iam_deny_policies = local._tenant_iam_deny_policies[each.key]",
            tf_text,
        )
        # Consolidates all enabled rules into 1 policy per (env, tenant) folder
        # and creates 0 policies when all sub-toggles are false.
        self.assertIn("tenant-baseline-lockdown = {", tf_text)
        self.assertIn("length(rules) == 0", tf_text)
        for old_policy_key in (
            "tenant-gke-fleet-registration = {",
            "kms-key-destruction = {",
            "sa-impersonation-lockdown = {",
        ):
            self.assertNotIn(old_policy_key, tf_text)
        self.assertRegex(
            vars_block,
            r"kms_iam_lockdown\s*=\s*optional\(bool,\s*true\)",
        )
        # Read-only plan SAs receive roles/iam.denyReviewer when enabled.
        self.assertIn('"roles/iam.denyReviewer"', tf_text)
        self.assertIn("var.automation.service_accounts.resman-r", tf_text)
        self.assertIn('"roles/iam.denyReviewer"', net_tf_text)
        self.assertIn('"roles/resourcemanager.tagViewer"', net_tf_text)
        # SA impersonation lockdown defaults to false and requires a tag scope.
        self.assertRegex(
            vars_block,
            r"sa_impersonation_lockdown\s*=\s*optional\(bool,\s*false\)",
        )
        self.assertIn(
            "var.iam_deny_guardrails.sa_impersonation_tag != null",
            vars_block,
        )
        # Folder service agents and tenant-self-iac-sa are exempted on
        # automation-facing rules (SA lockdown and KMS IAM companion rule).
        self.assertIn("module.tenant-self-iac-sa[k].email", tf_text)
        self.assertIn(
            "${module.tenant-top-folders[k].id}/type/ServiceAgent",
            tf_text,
        )
        # Non-prod mapping covers Dev, Int, Test (!= "prod") vs Prod only.
        self.assertIn('lower(v.env) != "prod"', tf_text)
        self.assertIn('lower(v.env) == "prod"', tf_text)
        self.assertNotIn('lower(v.env) == "dev"', tf_text)
        # Key-disable, actAs, and expanded GKE Hub protections must be present.
        self.assertIn(
            '"cloudkms.googleapis.com/cryptoKeyVersions.update"', tf_text
        )
        self.assertIn('"iam.googleapis.com/serviceAccounts.actAs"', tf_text)
        self.assertIn(
            '"gkehub.googleapis.com/rbacrolebindings.create"', tf_text
        )
        self.assertIn('"gkehub.googleapis.com/namespaces.create"', tf_text)
        self.assertIn('"gkehub.googleapis.com/gateway.post"', tf_text)
        self.assertNotIn("attribute.repository", tf_text)

    def test_stage2b_uses_project_module_tag_condition_and_full_verbs(self):
        iam_deny_tf = (_STAGE2B_DIR / "iam-deny.tf").read_text(encoding="utf-8")
        net_vdss_tf = (_STAGE2B_DIR / "net-vdss.tf").read_text(encoding="utf-8")
        vars_block = _extract_variable_block(
            _STAGE2B_DIR, "iam_deny_guardrails"
        )

        self.assertIn("tags = local._ngfw_bootstrap_project_tags", net_vdss_tf)
        self.assertIn(
            'source                  = "../../../modules/project"',
            iam_deny_tf,
        )
        self.assertIn(
            "iam_by_principals_additive = local._ngfw_bootstrap_readonly_iam",
            iam_deny_tf,
        )
        self.assertRegex(
            iam_deny_tf,
            r"iam_deny_policies\s*=\s*local\._ngfw_bootstrap_deny_policies",
        )
        # Denial conditions only support resource tag CEL functions.
        self.assertIn("resource.matchTag(", iam_deny_tf)
        self.assertNotIn("resource.name.startsWith", iam_deny_tf)
        # Expanded storage verbs and tag-binding removal must be denied.
        for perm in (
            "storage.googleapis.com/buckets.deleteTagBinding",
            "storage.googleapis.com/buckets.createTagBinding",
            "storage.googleapis.com/buckets.relocate",
            "storage.googleapis.com/folders.create",
            "storage.googleapis.com/multipartUploads.abort",
            "storage.googleapis.com/objects.createContext",
        ):
            self.assertIn(f'"{perm}"', iam_deny_tf)
        # Tag binding tracks bucket replacement and deny policy waits on all
        # bootstrap objects plus the bucket IAM binding.
        self.assertIn(
            'resource "terraform_data" "ngfw_bootstrap_bucket_ids"',
            iam_deny_tf,
        )
        self.assertIn("replace_triggered_by = [", iam_deny_tf)
        for dep in (
            "google_storage_bucket_iam_binding.binding",
            "google_storage_bucket_object.bootstrap_xml",
            "google_storage_bucket_object.config_folders",
            "google_storage_bucket_object.content_folders",
            "google_storage_bucket_object.init_cfg",
            "google_storage_bucket_object.license_folders",
            "google_storage_bucket_object.software_folders",
        ):
            self.assertIn(dep, iam_deny_tf)
        # Exempt only specific NGFW SA and ServiceAgent set, never all SAs.
        self.assertIn("module.ngfw-service-account.email", iam_deny_tf)
        self.assertIn("/type/ServiceAgent", iam_deny_tf)
        self.assertNotIn("/type/ServiceAccount", iam_deny_tf)
        self.assertNotIn("attribute.repository", iam_deny_tf)
        # Fail-closed validation prevents locking out Stage 2 automation.
        self.assertIn(
            "try(var.service_accounts.networking, null) != null", vars_block
        )

    def test_stage3_enforces_acm_lockdown_and_auto_exempts_security_sa(self):
        iam_deny_tf = (_STAGE3_DIR / "iam-deny.tf").read_text(encoding="utf-8")
        vars_block = _extract_variable_block(_STAGE3_DIR, "iam_deny_guardrails")
        sa_block = _extract_variable_block(_STAGE3_DIR, "service_accounts")

        self.assertIn(
            'resource "google_iam_deny_policy" "acm_lockdown"', iam_deny_tf
        )
        self.assertIn(
            "count        = var.iam_deny_guardrails.enabled ? 1 : 0",
            iam_deny_tf,
        )
        self.assertIn(
            'urlencode(\n    "cloudresourcemanager.googleapis.com/'
            '${local._acm_deny_parent}"',
            iam_deny_tf,
        )
        self.assertIn("security             = optional(string)", sa_block)
        self.assertIn("security-r           = optional(string)", sa_block)
        self.assertIn("try(var.service_accounts.security, null)", iam_deny_tf)
        self.assertIn(
            "try(length(trimspace(var.service_accounts.security)) > 0, false)",
            vars_block,
        )
        self.assertIn(
            "length(var.iam_deny_guardrails.exception_principals) > 0",
            vars_block,
        )
        self.assertNotIn("attribute.repository", iam_deny_tf)

    def test_readmes_document_guardrails_and_deny_admin_prerequisite(self):
        for stage_dir in (_STAGE1_DIR, _STAGE2B_DIR, _STAGE3_DIR):
            with self.subTest(stage=stage_dir.name):
                readme = (stage_dir / "README.md").read_text(encoding="utf-8")
                self.assertIn("### IAM Deny guardrails", readme)
                self.assertIn("iam_deny_guardrails", readme)
                self.assertIn("roles/iam.denyAdmin", readme)
                self.assertIn("roles/iam.denyReviewer", readme)

        stage1_readme = (_STAGE1_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("-parallelism=1", stage1_readme)
        self.assertIn("5 Read", stage1_readme)

        for stage_dir in (_STAGE2B_DIR, _STAGE3_DIR):
            with self.subTest(stage=stage_dir.name, check="adc_warning"):
                readme = (stage_dir / "README.md").read_text(encoding="utf-8")
                self.assertIn("principal://goog/subject/<email>", readme)


if __name__ == "__main__":
    unittest.main()
