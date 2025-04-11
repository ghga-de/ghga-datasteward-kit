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

"""Data loading related functionality."""

from pathlib import Path

from metldata.load.client import upload_artifacts_via_http_api as upload_metadata
from metldata.load.config import ArtifactLoaderClientConfig

from ghga_datasteward_kit.utils import STEWARD_TOKEN, load_config_yaml


class LoadConfig(ArtifactLoaderClientConfig):
    """Load Config"""


def load(*, config_path: Path) -> None:
    """Load file and metadata artifacts to the loader API."""
    config = load_config_yaml(path=config_path, config_cls=LoadConfig)
    token = STEWARD_TOKEN.read_token()

    upload_metadata(config=config, token=token)
