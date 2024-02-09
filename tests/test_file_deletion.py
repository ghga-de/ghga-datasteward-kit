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
"""Tests for PCS file deletion call."""

import logging
from pathlib import Path

import pytest

from ghga_datasteward_kit.cli.file import delete_file
from ghga_datasteward_kit.config import FileDeletionConfig
from ghga_datasteward_kit.utils import DELETION_TOKEN, load_config_yaml

CONFIG_PATH = Path(__file__).parent / "fixtures" / "file_deletion_config.yaml"


@pytest.mark.parametrize("file_id", ["exists", "fake"])
def test_pcs_call(caplog, monkeypatch, httpx_mock, tmp_path, file_id: str):
    """Call mock endpoint to validate client functionality."""
    # only capture file deletion logs
    caplog.set_level(logging.INFO, logger="ghga_datasteward_kit.file_deletion")
    config = load_config_yaml(path=CONFIG_PATH, config_cls=FileDeletionConfig)
    base = config.file_deletion_baseurl.rstrip("/")
    endpoint = config.file_deletion_endpoint.strip("/")
    url = f"{base}/{endpoint}/{file_id}"

    # mock endpoints
    if file_id == "exists":
        httpx_mock.add_response(method="DELETE", url=url, status_code=202)
        message = f"Successfully sent deletion request for file '{file_id}'."
    else:
        status_code = 404
        httpx_mock.add_response(method="DELETE", url=url, status_code=status_code)
        message = (
            f"Deletion request to '{url}' failed with response code {status_code}."
        )

    caplog.clear()
    with monkeypatch.context() as patch:
        # set up token in tmp dir for testing
        patch.setattr(DELETION_TOKEN, "token_path", tmp_path / "_token.txt")
        patch.setattr(DELETION_TOKEN, "token_hash_path", tmp_path / "_token_hash.txt")
        DELETION_TOKEN.save_token_and_hash()

        delete_file(file_id=file_id, config_path=CONFIG_PATH)

        assert len(caplog.messages) == 1
        assert message in caplog.messages
