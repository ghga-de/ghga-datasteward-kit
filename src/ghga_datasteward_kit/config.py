# Copyright 2021 - 2025 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Collection of all config classes."""

from ghga_datasteward_kit.file_deletion import FileDeletionConfig
from ghga_datasteward_kit.file_ingest import IngestConfig
from ghga_datasteward_kit.loading import LoadConfig
from ghga_datasteward_kit.metadata import MetadataConfig
from ghga_datasteward_kit.s3_upload import Config as S3UploadConfig

CONFIG_CLASSES = {
    "s3_upload": S3UploadConfig,
    "purge": FileDeletionConfig,
    "metadata": MetadataConfig,
    "load": LoadConfig,
    "ingest": IngestConfig,
}
