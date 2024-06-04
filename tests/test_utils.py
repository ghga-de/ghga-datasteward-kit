# Copyright 2021 - 2024 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Test for utils package"""

import pytest

from ghga_datasteward_kit.s3_upload.utils import join_url_parts


@pytest.mark.parametrize(
    "base, paths, expected",
    [
        # Base URL without trailing slash
        ("http://fis:8080", ["/some"], "http://fis:8080/some"),
        ("http://fis:8080", ["some"], "http://fis:8080/some"),
        ("http://fis:8080", ["some", "extra"], "http://fis:8080/some/extra"),
        ("http://fis:8080", ["some", "/extra"], "http://fis:8080/some/extra"),
        (
            "http://fis:8080",
            ["/some", "more", "extra"],
            "http://fis:8080/some/more/extra",
        ),
        # Base URL with trailing slash
        ("http://fis:8080/", ["some"], "http://fis:8080/some"),
        ("http://fis:8080/", ["some", "more"], "http://fis:8080/some/more"),
        (
            "http://fis:8080/",
            ["/some", "more", "/extra"],
            "http://fis:8080/some/more/extra",
        ),
        # Base URL with nested paths without trailing slash
        ("https://testing/api/fis", ["/some"], "https://testing/api/fis/some"),
        ("https://testing/api/fis", ["some"], "https://testing/api/fis/some"),
        (
            "https://testing/api/fis",
            ["some", "more"],
            "https://testing/api/fis/some/more",
        ),
        (
            "https://testing/api/fis",
            ["/some", "more"],
            "https://testing/api/fis/some/more",
        ),
        # Base URL with nested paths with trailing slash
        ("https://testing/api/fis/", ["some"], "https://testing/api/fis/some"),
        (
            "https://testing/api/fis/",
            ["some", "more"],
            "https://testing/api/fis/some/more",
        ),
        (
            "https://testing/api/fis/",
            ["/some", "more", "extra"],
            "https://testing/api/fis/some/more/extra",
        ),
    ],
)
def test_join_url_parts(base, paths, expected):
    """Test join_url_parts function"""
    result = join_url_parts(base, *paths)
    assert result == expected
