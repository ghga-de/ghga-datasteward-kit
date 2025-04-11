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

"""Test for utils package"""

import pytest

from ghga_datasteward_kit.utils import path_join


@pytest.mark.parametrize(
    "base, paths, expected",
    [
        # Base URL without trailing slash
        ("http://fis:8080", ["/a"], "http://fis:8080/a"),
        ("http://fis:8080", ["a"], "http://fis:8080/a"),
        ("http://fis:8080", ["a", "b"], "http://fis:8080/a/b"),
        ("http://fis:8080", ["a", "/b"], "http://fis:8080/a/b"),
        (
            "http://fis:8080",
            ["/a", "b", "c"],
            "http://fis:8080/a/b/c",
        ),
        # Base URL with trailing slash
        ("http://fis:8080/", ["a"], "http://fis:8080/a"),
        ("http://fis:8080/", ["a", "b"], "http://fis:8080/a/b"),
        (
            "http://fis:8080/",
            ["/a", "b", "/c"],
            "http://fis:8080/a/b/c",
        ),
        # Base URL with nested paths without trailing slash
        ("https://test/api/fis", ["/a"], "https://test/api/fis/a"),
        ("https://test/api/fis", ["a"], "https://test/api/fis/a"),
        (
            "https://test/api/fis",
            ["a", "b"],
            "https://test/api/fis/a/b",
        ),
        (
            "https://test/api/fis",
            ["/a", "b"],
            "https://test/api/fis/a/b",
        ),
        # Base URL with nested paths with trailing slash
        ("https://test/api/fis/", ["a"], "https://test/api/fis/a"),
        ("https://test/api/fis/", ["a", "b"], "https://test/api/fis/a/b"),
        ("https://test/api/fis/", ["/a", "b", "c"], "https://test/api/fis/a/b/c"),
        # Base URL as POSIX paths with combined parts
        ("folder/", ["a", "b", "c/"], "folder/a/b/c/"),
        ("/folder", ["/a", "b", "c"], "/folder/a/b/c"),
        ("folder", ["a", "b", "c", "d", "e"], "folder/a/b/c/d/e"),
        ("folder", ["/a/b"], "folder/a/b"),
        ("/folder/a", ["/b", "c"], "/folder/a/b/c"),
        ("folder/a", ["/b/c"], "folder/a/b/c"),
        ("folder/a/b/", ["c", "/d/"], "folder/a/b/c/d/"),
        ("folder/a/b/", ["c", "/d/e/f", "g"], "folder/a/b/c/d/e/f/g"),
    ],
)
def test_path_join(base, paths, expected):
    """Test path_join function"""
    result = path_join(base, *paths)
    assert result == expected
