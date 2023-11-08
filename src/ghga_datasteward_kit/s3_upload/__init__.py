# Copyright 2021 - 2023 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
# for the German Human Genome-Phenome Archive (GHGA)
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
#
"""Contains functionality to encrypt data using Crypt4GH and directly uploading it to S3
object storage."""

from ghga_datasteward_kit.s3_upload.config import Config, LegacyConfig  # noqa: F401
from ghga_datasteward_kit.s3_upload.entrypoint import legacy_main, main  # noqa: F401
from ghga_datasteward_kit.utils import load_config_yaml  # noqa: F401
