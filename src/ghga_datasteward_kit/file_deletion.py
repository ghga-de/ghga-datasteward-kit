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
#
"""Provides functionality to request file service data deleteion."""

import logging
from pathlib import Path

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings

from ghga_datasteward_kit.utils import DELETION_TOKEN, load_config_yaml, path_join

log = logging.getLogger(__name__)


class FileDeletionConfig(BaseSettings):
    """Config for calling the PCS file deletion endpoint"""

    file_deletion_baseurl: str = Field(
        default=...,
        description=(
            "Base URL under which the file deletion endpoint is available."
            + " This is an endpoint exposed by GHGA Central. This value is provided by"
            + " GHGA Central on demand."
        ),
    )
    file_deletion_endpoint: str = Field(
        default="/files",
        description=(
            "Path to the PCS endpoint (relative to baseurl) expecting a delete request including"
            + " the ID of the file for which data should be deleted in the file services."
        ),
    )


def main(*, file_id: str, config_path: Path):
    """Call PCS to delete all data in the file services for the given file ID."""
    config = load_config_yaml(path=config_path, config_cls=FileDeletionConfig)

    url = path_join(
        config.file_deletion_baseurl, config.file_deletion_endpoint, file_id
    )

    token = DELETION_TOKEN.read_token()
    headers = httpx.Headers({"Authorization": f"Bearer {token}"})

    with httpx.Client() as client:
        response = client.delete(url=url, headers=headers, timeout=60)

        status_code = response.status_code
        if status_code != 202:
            log.error(
                f"Deletion request to '{url}' failed with response code {status_code}."
            )
            return

    log.info(f"Successfully sent deletion request for file '{file_id}'.")
