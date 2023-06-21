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
"""Interaction with file ingest service"""

from pathlib import Path
from typing import Callable

import httpx
from pydantic import BaseSettings, Field, ValidationError

from ghga_datasteward_kit import models, utils


class IngestConfig(BaseSettings):
    """Config options for calling the file ingest endpoint"""

    file_ingest_url: str = Field(
        ..., description="Base URL under which the /ingest endpoint is available."
    )
    pubkey: str = Field(
        ..., description="Public key used for encryption of the payload."
    )
    token: str = Field(
        ...,
        description="Token used for authentication against the file ingest service.",
    )


def main(
    input_directory: Path,
    config_path: Path,
    id_generator: Callable[[], str],
):
    """Handle ingestion of a folder of s3 upload file metadata"""

    config = utils.load_config_yaml(path=config_path, config_cls=IngestConfig)

    errors = {}

    for in_path, file_id in zip(input_directory.iterdir(), id_generator()):
        if in_path.suffix == ".json":
            try:
                file_ingest(in_path=in_path, file_id=file_id, config=config)
            except (ValidationError, ValueError) as error:
                errors[in_path.resolve()] = str(error)
                continue

    if errors:
        print(f"Encountered {len(errors)} errors during processing.")
        for file_path, cause in errors.items():
            print(f" -{file_path}: {cause}")
    else:
        print("Sucessfully sent all file upload metadata for ingest.")


def file_ingest(in_path: Path, file_id: str, config: IngestConfig):
    """
    Transform from s3 upload output representation to what the file ingest service expects.
    Then call the ingest endpoint
    """

    print(f"Ingesting file upload metadata for {in_path}.")

    output_metadata = models.OutputMetadata.load(input_path=in_path)
    upload_metadata = output_metadata.to_upload_metadata(file_id=file_id)
    encrypted = upload_metadata.encrypt_metadata(pubkey=config.pubkey)

    headers = {"Authorization": f"Bearer {config.token}"}

    with httpx.Client() as client:
        response = client.post(
            f"{config.endpoint_base}", json=encrypted.dict(), headers=headers
        )

        if response.status_code != 202:
            if response.status_code in (403, 422, 500):
                raise ValueError(response.json()["detail"])

            raise ValueError(
                f"Unxpected server response: {response.status_code}: {response.text}"
            )
