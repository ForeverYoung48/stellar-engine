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

"""Verifies Stage 0 monitoring project and SIEM Pub/Sub hardening invariants."""

import pathlib
import re
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_BOOTSTRAP_DIR = _REPO_ROOT / "fast/stages-aw/0-bootstrap"


def _block(text: str, header: str) -> str:
    pattern = re.compile(re.escape(header) + r"\s*\{[\s\S]*?\n\}", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        raise AssertionError(f"Block not found: {header}")
    return match.group(0)


class TestBootstrapMonitoringAndSiem(unittest.TestCase):
    def test_monitoring_project_hardening_and_least_privilege_iam(self):
        monitoring_tf = (_BOOTSTRAP_DIR / "monitoring.tf").read_text(
            encoding="utf-8"
        )
        block = _block(monitoring_tf, 'module "monitoring-project"')
        self.assertIn('default_service_account = "deprivilege"', block)
        self.assertRegex(
            block,
            r'lien_reason\s*=\s*"Protected by default as a core project\."',
        )
        self.assertIn("depends_on = [module.organization-logging]", block)
        self.assertRegex(
            block,
            r'"roles/owner"\s*=\s*compact\(\[\s*'
            r"module\.automation-tf-bootstrap-sa\.iam_email,\s*"
            r'var\.bootstrap_user\s*!=\s*null\s*\?\s*"user:\$\{'
            r'var\.bootstrap_user\}"\s*:\s*null',
        )
        self.assertIn(
            '"roles/viewer" = [module.automation-tf-bootstrap-r-sa.iam_email]',
            block,
        )
        self.assertNotIn("tenants", block)

        monitored_block = _block(
            monitoring_tf,
            'resource "google_monitoring_monitored_project" "default"',
        )
        self.assertRegex(
            monitored_block,
            r"depends_on\s*=\s*\[module\.monitoring-project\]",
        )

    def test_monitoring_api_enabled_on_bootstrap_and_automation(self):
        enable_services = (_BOOTSTRAP_DIR / "enableServices.sh").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            enable_services,
            r'list_of_services="[^"]*\bmonitoring\b[^"]*"',
        )
        automation_tf = (_BOOTSTRAP_DIR / "automation.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn('"monitoring.googleapis.com"', automation_tf)

    def test_log_export_and_kms_avoid_hardcoded_service_accounts(self):
        kms_tf = (_BOOTSTRAP_DIR / "kms.tf").read_text(encoding="utf-8")
        log_export_tf = (_BOOTSTRAP_DIR / "log-export.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn("local.has_pubsub_export", kms_tf)
        self.assertIn(
            'module.log-export-project.service_agents["pubsub"].iam_email',
            kms_tf,
        )
        self.assertNotIn("@gcp-sa-logging", kms_tf)
        self.assertNotIn("@gcp-sa-logging", log_export_tf)
        self.assertIn('"${pair[0]}-${pair[1]}"', log_export_tf)
        self.assertIn(
            'resource "google_kms_crypto_key_iam_member" "siem_export_pubsub"',
            log_export_tf,
        )
        siem_block = _block(log_export_tf, 'module "siem-export-pubsub"')
        self.assertIn(
            "google_kms_crypto_key_iam_member.siem_export_pubsub",
            siem_block,
        )

    def test_tfvars_keeps_auto_tfvars_schema_unchanged(self):
        outputs_tf = (_BOOTSTRAP_DIR / "outputs.tf").read_text(encoding="utf-8")
        tfvars_match = re.search(r"tfvars\s*=\s*\{[\s\S]*?\n  \}", outputs_tf)
        self.assertIsNotNone(tfvars_match)
        self.assertNotIn("monitoring_project_id", tfvars_match.group(0))
        self.assertIn('output "monitoring_project_id"', outputs_tf)


if __name__ == "__main__":
    unittest.main()
