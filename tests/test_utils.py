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

from ghga_datasteward_kit.s3_upload.utils import safe_urljoin


def test_safe_urljoin():
    """Test custom safe_urljoin function."""
    test_cases = {
        "http://fis:8080": [
            (["/some"], "http://fis:8080/some"),
            (["some"], "http://fis:8080/some"),
            (["some", "extra"], "http://fis:8080/some/extra"),
            (["some", "/extra"], "http://fis:8080/some/extra"),
            (["/some", "more", "extra"], "http://fis:8080/some/more/extra"),
        ],
        "http://fis:8080/": [
            (["/some"], "http://fis:8080/some"),
            (["some", "more"], "http://fis:8080/some/more"),
            (["/some", "more", "/extra"], "http://fis:8080/some/more/extra"),
        ],
        "https://testing/api/fis": [
            (["/some"], "https://testing/api/fis/some"),
            (["some"], "https://testing/api/fis/some"),
            (["some", "more"], "https://testing/api/fis/some/more"),
            (["/some", "more"], "https://testing/api/fis/some/more"),
        ],
        "https://testing/api/fis/": [
            (["/some"], "https://testing/api/fis/some"),
            (["some", "more"], "https://testing/api/fis/some/more"),
            (["/some", "/more", "extra"], "https://testing/api/fis/some/more/extra"),
        ],
    }

    for base, paths_with_expected in test_cases.items():
        for paths, expected in paths_with_expected:
            result = safe_urljoin(base, *paths)
            assert result == expected
