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
"""Tests for tools/lint.sh fail-closed execution and clean-repo pass."""

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


def _install_stub_bins(stub_bin: Path) -> None:
    """Installs lightweight stub binaries for uv and terraform in stub_bin."""
    stub_bin.mkdir(parents=True, exist_ok=True)
    uv_stub = stub_bin / "uv"
    uv_stub.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "run" ]; then shift; fi\n'
        'if [ "$1" = "--locked" ]; then shift; fi\n'
        'if [ "$1" = "python" ]; then\n'
        "  shift\n"
        f'  exec "{sys.executable}" "$@"\n'
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    uv_stub.chmod(uv_stub.stat().st_mode | stat.S_IXUSR)

    tf_stub = stub_bin / "terraform"
    tf_stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tf_stub.chmod(tf_stub.stat().st_mode | stat.S_IXUSR)


class TestLintSh(unittest.TestCase):
    """Validates tools/lint.sh syntax and fail-closed error handling."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent.parent
        cls.lint_script = cls.repo_root / "tools" / "lint.sh"

    def test_lint_sh_bash_syntax_valid(self):
        """tools/lint.sh must have valid bash syntax."""
        proc = subprocess.run(
            ["bash", "-n", str(self.lint_script)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"Bash syntax error in lint.sh: {proc.stderr}",
        )

    def test_lint_sh_fails_closed_when_checks_fail(self):
        """tools/lint.sh must exit non-zero when a check fails."""
        with tempfile.TemporaryDirectory() as td:
            sandbox = Path(td)
            tools_dir = sandbox / "tools"
            tools_dir.mkdir()
            for fname in (
                "lint.sh",
                "check_boilerplate.py",
                "check_documentation.py",
                "check_links.py",
                "check_names.py",
                "validate_metadata.py",
                "tfdoc.py",
                "bpmetadataschema.json",
            ):
                src = self.repo_root / "tools" / fname
                if src.is_file():
                    shutil.copy2(src, tools_dir / fname)
            tflint_stub = tools_dir / "tflint.sh"
            tflint_stub.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            tflint_stub.chmod(tflint_stub.stat().st_mode | stat.S_IXUSR)

            for dname in ("modules", "fast", "blueprints"):
                (sandbox / dname).mkdir()
            (sandbox / "fast" / "stages-aw").mkdir()
            (sandbox / "default-versions.tf").write_text(
                "# Copyright 2026 Google LLC\n", encoding="utf-8"
            )
            # Write a Python file missing the Apache 2.0 header
            (sandbox / "blueprints" / "missing_header.py").write_text(
                "x = 1\n", encoding="utf-8"
            )

            stub_bin = sandbox / ".git" / "stub_bin"
            _install_stub_bins(stub_bin)
            env = os.environ.copy()
            env["PATH"] = f"{stub_bin}:{env.get('PATH', '')}"

            proc = subprocess.run(
                ["bash", str(tools_dir / "lint.sh")],
                cwd=str(sandbox),
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                "lint.sh must exit non-zero when boilerplate fails",
            )
            self.assertIn("Lint checks FAILED", proc.stdout)
            self.assertIn("Boilerplate check", proc.stdout)
