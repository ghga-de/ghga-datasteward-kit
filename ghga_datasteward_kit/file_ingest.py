# Copyright 2023 Universität Tübingen, DKFZ and EMBL
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
"""TODO"""

from pathlib import Path

from ghga_datasteward_kit import models


def main(input_directory: Path):
    """TODO"""

    for in_path in input_directory.iterdir():
        if in_path.suffix == ".json":
            output_metadata = models.OutputMetadata.load(input_path=in_path)
            upload_metadata = output_metadata.to_upload_metadata(file_id="")
            _ = upload_metadata.encrypt_metadata(public_key="")
