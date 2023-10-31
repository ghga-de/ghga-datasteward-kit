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

"""Test adjustment code for part size"""

from ghga_datasteward_kit.s3_upload import Config
from ghga_datasteward_kit.s3_upload.utils import check_adjust_part_size
from tests.fixtures.config import legacy_config_fixture  # noqa: F401


def test_check_adjust_part_size(legacy_config_fixture: Config):  # noqa: F811
    """Test adaptive adjustment"""
    legacy_config_fixture.part_size = 16
    file_size = 16 * 80_000 * 1024**2
    check_adjust_part_size(config=legacy_config_fixture, file_size=file_size)
    adjusted_part_size = legacy_config_fixture.part_size / 1024**2
    assert adjusted_part_size == 256


def test_check_adjust_part_size_lower_bound(
    legacy_config_fixture: Config,  # noqa: F811
):
    """Test lower bound"""
    lower_expect = 5 * 1024**2
    legacy_config_fixture.part_size = 4
    check_adjust_part_size(config=legacy_config_fixture, file_size=32 * 1024**2)
    assert legacy_config_fixture.part_size == lower_expect


def test_check_adjust_part_size_upper_bound(
    legacy_config_fixture: Config,  # noqa: F811
):
    """Test upper bound"""
    upper_expect = 5 * 1024**3
    legacy_config_fixture.part_size = int(5.1 * 1024)
    check_adjust_part_size(config=legacy_config_fixture, file_size=32 * 1024**2)
    assert legacy_config_fixture.part_size == upper_expect
