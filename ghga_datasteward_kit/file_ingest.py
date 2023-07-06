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
from metldata.submission_registry.submission_store import (
    SubmissionStore,
    SubmissionStoreConfig,
)
from pydantic import Field, ValidationError

from ghga_datasteward_kit import models, utils


class IngestConfig(SubmissionStoreConfig):
    """Config options for calling the file ingest endpoint"""

    file_ingest_url: str = Field(
        ..., description="Base URL under which the /ingest endpoint is available."
    )
    file_ingest_pubkey: str = Field(
        ..., description="Public key used for encryption of the payload."
    )
    input_dir: Path = Field(
        ...,
        description="Path to directory containing output files from the "
        + "upload/batch_upload command.",
    )
    map_files_fields: list[str] = Field(
        ["study_files"],
        description="Names of the accession map fields for looking up the"
        + " alias->accession mapping.",
    )


def alias_to_accession(
    alias: str, map_fields: list[str], submission_store: SubmissionStore
) -> str:
    """Get all submissions to retrieve valid accessions from corresponding file aliases"""

    submission_ids = submission_store.get_all_submission_ids()

    all_submission_map = {}

    for submission_id in submission_ids:
        submission = submission_store.get_by_id(submission_id=submission_id)
        for field in map_fields:
            if field not in submission.accession_map:
                raise ValueError(
                    f"Configured field {field} not found in accession map."
                )
            all_submission_map.update(submission.accession_map[field])

    accession = all_submission_map.get(alias)

    if accession is None:
        raise ValueError(f"No accession exists for file alias {alias}")

    return accession


def main(
    config_path: Path,
):
    """Handle ingestion of a folder of s3 upload file metadata"""

    config = utils.load_config_yaml(path=config_path, config_cls=IngestConfig)
    token = utils.read_token()

    errors = {}

    for in_path in config.input_dir.iterdir():
        if in_path.suffix != ".json":
            continue
        try:
            file_ingest(in_path=in_path, token=token, config=config)
        except (ValidationError, ValueError) as error:
            errors[in_path.resolve()] = str(error)
            continue

    return errors


def file_ingest(
    in_path: Path,
    token: str,
    config: IngestConfig,
    alias_to_id: Callable[[str, list[str], SubmissionStore], str] = alias_to_accession,
):
    """
    Transform from s3 upload output representation to what the file ingest service expects.
    Then call the ingest endpoint
    """

    submission_store = SubmissionStore(config=config)

    output_metadata = models.OutputMetadata.load(input_path=in_path)
    file_id = alias_to_id(
        output_metadata.alias, config.map_files_fields, submission_store
    )
    upload_metadata = output_metadata.to_upload_metadata(file_id=file_id)
    encrypted = upload_metadata.encrypt_metadata(pubkey=config.file_ingest_pubkey)

    headers = {"Authorization": f"Bearer {token}"}

    with httpx.Client() as client:
        response = client.post(
            f"{config.file_ingest_url}", json=encrypted.dict(), headers=headers
        )

        if response.status_code != 202:
            if response.status_code in (403, 422, 500):
                raise ValueError(response.json()["detail"])

            raise ValueError(
                f"Unxpected server response: {response.status_code}: {response.text}"
            )
