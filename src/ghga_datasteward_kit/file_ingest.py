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
"""Interaction with file ingest service"""

import logging
from collections.abc import Callable
from pathlib import Path

import httpx
from metldata.submission_registry.submission_store import (
    SubmissionStore,
    SubmissionStoreConfig,
)
from pydantic import Field, ValidationError

from ghga_datasteward_kit import models, utils

LOG = logging.getLogger(__name__)


class IngestConfig(SubmissionStoreConfig):
    """Config options for calling the file ingest endpoint"""

    file_ingest_baseurl: str = Field(
        default=...,
        description=(
            "Base URL under which the /ingest endpoint is available."
            + " This is an endpoint exposed by GHGA Central. This value is provided by"
            + " GHGA Central on demand."
        ),
    )
    file_ingest_federated_endpoint: str = Field(
        default="/federated/ingest_metadata",
        description=(
            "Path to the FIS endpoint (relative to baseurl) expecting the new style"
            + " upload metadata including a secret ID instead of the actual secret."
        ),
    )
    file_ingest_legacy_endpoint: str = Field(
        default="/legacy/ingest",
        description=(
            "Path to the FIS endpoint (relative to baseurl) expecting the old style"
            + "upload metadata including the encryption secret."
        ),
    )
    file_ingest_pubkey: str = Field(
        default=...,
        description=(
            "Public key provided by GHGA Central used to encrypt the communication with"
            + " GHGA Central."
        ),
    )
    input_dir: Path = Field(
        default=...,
        description="Path to directory containing output files from the "
        + "upload/batch_upload command.",
    )
    map_files_fields: list[str] = Field(
        default=["study_files"],
        description="Names of the accession map fields for looking up the"
        + " alias->accession mapping.",
    )
    selected_storage_alias: str = Field(
        default=...,
        description=(
            "Alias of the selected storage node/location. Has to match the backend configuration"
            + " and must also be present in the local storage configuration."
            + " During the later ingest phase, the alias will be validated by the File Ingest Service."
        ),
    )
    fallback_bucket_id: str = Field(
        default=...,
        description="Fallback bucket_id for older output metadata files that don't contain a bucket ID.",
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
    token = utils.STEWARD_TOKEN.read_token()

    errors = {}
    successes = set()

    for in_path in config.input_dir.iterdir():
        if in_path.suffix != ".json":
            continue
        try:
            file_ingest(in_path=in_path, token=token, config=config)
        except (ValidationError, ValueError) as error:
            errors[in_path.resolve()] = str(error)
            continue
        else:
            successes.add(in_path.resolve())

    return errors, successes


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
    try:
        output_metadata = models.OutputMetadata.load(
            input_path=in_path,
            selected_alias=config.selected_storage_alias,
            fallback_bucket=config.fallback_bucket_id,
        )
        endpoint = config.file_ingest_federated_endpoint
        LOG.info("Selected non-legacy endpoint %s for file %s.", endpoint, in_path)
    except (KeyError, ValidationError):
        output_metadata = models.LegacyOutputMetadata.load(
            input_path=in_path,
            selected_alias=config.selected_storage_alias,
            fallback_bucket=config.fallback_bucket_id,
        )
        endpoint = config.file_ingest_legacy_endpoint
        LOG.info("Selected legacy endpoint %s for file %s.", endpoint, in_path)

    endpoint_url = utils.path_join(config.file_ingest_baseurl, endpoint)

    submission_store = SubmissionStore(config=config)

    file_id = alias_to_id(
        output_metadata.alias, config.map_files_fields, submission_store
    )
    upload_metadata = output_metadata.to_upload_metadata(file_id=file_id)

    if isinstance(upload_metadata, models.LegacyMetadata):
        payload = upload_metadata.encrypt_metadata(public_key=config.file_ingest_pubkey)
    else:
        payload = upload_metadata

    headers = {"Authorization": f"Bearer {token}"}

    with httpx.Client() as client:
        response = client.post(
            f"{endpoint_url}",
            json=payload.model_dump(),
            headers=headers,
            timeout=60,
        )

        if response.status_code != 202:
            if response.status_code == 403:
                error = ValueError("Not authorized to access ingest endpoint.")
            elif response.status_code == 409:
                error = ValueError("Metadata has already been processed.")
            elif response.status_code == 422:
                error = ValueError("Could not decrypt received payload.")
            elif response.status_code == 500:
                error = ValueError(
                    "Internal file ingest service error or communication with vault failed."
                )
            else:
                error = ValueError(
                    f"Unexpected server response: {response.status_code}."
                )
            LOG.error(error)
            raise error

    LOG.info("Succesfully ingested metdatada for %s", in_path)
