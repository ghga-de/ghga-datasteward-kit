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

"""Metadata related tests"""

import os
import shutil
from pathlib import Path
from typing import Generator

import pytest

from ghga_datasteward_kit.cli.metadata import submit, transform
from tests.fixtures.metadata import (
    METADATA_CONFIG_PATH,
    ORIGINAL_METADATA_PATH,
    ORIGINAL_MODEL_PATH,
)


@pytest.fixture
def workdir(tmp_path: Path) -> Generator[Path, None, None]:
    """Prepare a work directory for"""
    tmp_path.joinpath("event_store").mkdir()
    tmp_path.joinpath("submission_store").mkdir()
    tmp_path.joinpath("accession_store").touch()
    shutil.copyfile(ORIGINAL_MODEL_PATH, tmp_path / "original_model.yaml")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(cwd)


def test_happy(workdir):
    """Test the 'happy' test case that is expected to run through without errors"""
    submit(
        submission_title="Test Title",
        submission_description="Test Description",
        metadata_path=ORIGINAL_METADATA_PATH,
        config_path=METADATA_CONFIG_PATH,
    )

    transform(config_path=METADATA_CONFIG_PATH)
