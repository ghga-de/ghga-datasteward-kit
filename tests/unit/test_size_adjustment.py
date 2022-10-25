# Copyright 2022 Universität Tübingen, DKFZ and EMBL
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

from src.s3_upload import Config, check_adjust_part_size

# if we need more tests that need actual not dummy values here, this should be a fixture
# instead
CONFIG = Config(
    s3_endpoint_url="s3://test_url",
    s3_access_key_id="test_access_key",
    s3_secret_access_key="test_secret_key",
    bucket_id="test_bucket",
    tmp_dir="/tmp",
    output_dir="/tmp/test_output",
)


def test_check_adjust_part_size():
    """Test adaptive adjustment"""
    CONFIG.part_size = 16
    file_size = 16 * 80_000 * 1024**2
    check_adjust_part_size(config=CONFIG, file_size=file_size)
    adjusted_part_size = CONFIG.part_size / 1024**2
    assert adjusted_part_size == 256


def test_check_adjust_part_size_lower_bound():
    """Test lower bound"""
    lower_expect = 5 * 1024**2
    CONFIG.part_size = 4
    check_adjust_part_size(config=CONFIG, file_size=32 * 1024**2)
    assert CONFIG.part_size == lower_expect


def test_check_adjust_part_size_upper_bound():
    """Test upper bound"""
    upper_expect = 5 * 1024**3
    CONFIG.part_size = int(5.1 * 1024)
    check_adjust_part_size(config=CONFIG, file_size=32 * 1024**2)
    assert CONFIG.part_size == upper_expect
