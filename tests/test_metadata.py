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

"""Metadata related tests"""

import os
import shutil
from collections.abc import Generator
from pathlib import Path

import pytest

from ghga_datasteward_kit.cli.metadata import compare_aliases, submit, transform
from tests.fixtures.metadata import (
    ARCHIVE_METADATA_CONFIG_PATH,
    ARCHIVE_ORIGINAL_METADATA_PATH,
    ARCHIVE_ORIGINAL_MODEL_PATH,
    METADATA_CONFIG_PATH,
    ORIGINAL_METADATA_PATH,
    ORIGINAL_MODEL_PATH,
)


def workdir_factory(original_model_path: Path):
    """Prepare a work directory for the provided model."""

    @pytest.fixture
    def workdir(tmp_path: Path) -> Generator[Path, None, None]:
        """Prepare a work directory for"""
        tmp_path.joinpath("event_store").mkdir()
        tmp_path.joinpath("submission_store").mkdir()
        tmp_path.joinpath("accession_store").touch()
        tmp_path.joinpath("artifact_model").touch()
        shutil.copyfile(original_model_path, tmp_path / "original_model.yaml")
        cwd = os.getcwd()
        os.chdir(tmp_path)
        yield tmp_path
        os.chdir(cwd)

    return workdir


example_workdir = workdir_factory(ORIGINAL_MODEL_PATH)
archive_workdir = workdir_factory(ARCHIVE_ORIGINAL_MODEL_PATH)


def test_happy(example_workdir: Path):
    """Test the 'happy' test case that is expected to run through without errors"""
    submit(
        submission_title="Test Title",
        submission_description="Test Description",
        metadata_path=ORIGINAL_METADATA_PATH,
        config_path=METADATA_CONFIG_PATH,
    )

    transform(config_path=METADATA_CONFIG_PATH)


def test_archive_happy(archive_workdir: Path):
    """Test the 'happy' test case that is expected to run through without errors"""
    submit(
        submission_title="Test Title",
        submission_description="Test Description",
        metadata_path=ARCHIVE_ORIGINAL_METADATA_PATH,
        config_path=ARCHIVE_METADATA_CONFIG_PATH,
    )

    transform(config_path=ARCHIVE_METADATA_CONFIG_PATH)


@pytest.mark.parametrize(
    "file_overview_path, output",
    [
        (
            Path("./tests/fixtures/files_to_upload/all_accounted_for.tsv"),
            "Success: All files in all_accounted_for.tsv are accounted for in metadata.json",
        ),
        (
            Path("./tests/fixtures/files_to_upload/1_missing.tsv"),
            "The following file aliases are missing from metadata.json:\n- MISSING1",
        ),
        (
            Path("./tests/fixtures/files_to_upload/3_missing.tsv"),
            "The following file aliases are missing from metadata.json:\n- MISSING1\n- MISSING2\n- MISSING3",
        ),
    ],
)
def test_compare_aliases(file_overview_path: Path, output: str, capsys):
    """Test the `compare_aliases` function and verify the printed output."""
    compare_aliases(
        metadata_path=Path("./tests/fixtures/metadata.json"),
        tsv=file_overview_path,
    )
    captured = capsys.readouterr()
    assert captured.out.strip() == output
