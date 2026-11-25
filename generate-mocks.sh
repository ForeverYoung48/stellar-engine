#!/bin/bash
# Copyright 2025 Google LLC
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

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

STAGES=(
  "fast/stages-aw/0-bootstrap"
  "fast/stages-aw/1-resman"
  "fast/stages-aw/2-networking-a-fedramp"
  "fast/stages-aw/2-networking-b-il5-ngfw"
  "fast/stages-aw/3-security"
)

MOCK_VERSIONS='terraform {
  required_version = ">= 1.12.2"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 8.6.0, < 9.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 8.6.0, < 9.0.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.1"
    }
    external = {
      source  = "hashicorp/external"
      version = ">= 2.3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
  }
}'

# Generate mock-versions.tf only when a stage has no checked-in versions.tf.
for stage in "${STAGES[@]}"; do
  stage_dir="${SCRIPT_DIR}/${stage}"
  if [[ -f "${stage_dir}/versions.tf" ]]; then
    rm -f "${stage_dir}/mock-versions.tf"
    continue
  fi
  printf '%s\n' "${MOCK_VERSIONS}" > "${stage_dir}/mock-versions.tf"
done
