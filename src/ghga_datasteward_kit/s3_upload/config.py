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
#
"""S3 upload specific configuration."""

import subprocess  # nosec
from pathlib import Path

from pydantic import Field, NonNegativeInt, PositiveInt, SecretStr, field_validator
from pydantic_settings import BaseSettings


def expand_env_vars_in_path(path: Path) -> Path:
    """Expand environment variables in a Path."""
    with subprocess.Popen(  # noqa: S602
        f"realpath {path}",
        shell=True,
        stdout=subprocess.PIPE,
    ) as process:
        if process.wait() != 0 or not process.stdout:
            raise RuntimeError(f"Parsing of path failed: {path}")

        output = process.stdout.read().decode("utf-8").strip()

    return Path(output)


class NoEndpointURLS3Config(BaseSettings):
    """Custom implementation of the corresponding hexkit class to initialize with empty URLs"""

    s3_access_key_id: SecretStr = Field(
        default=...,
        description=(
            "This parameter plus the s3_secret_access_key serve as credentials for"
            + " accessing the internal staging bucket (as in"
            + " `bucket_id`) on the local data hub's S3 server with s3:GetObject and"
            + " s3:PutObject privileges. These credentials should"
            + " never be shared with GHGA Central."
        ),
    )
    s3_secret_access_key: SecretStr = Field(
        default=...,
        description=("Secret access key corresponding to the `s3_access_key_id`."),
    )


class S3ObjectStorageNodeConfig(BaseSettings):
    """Custom implementation of the corresponding service commons class to initialize with empty URLs"""

    bucket_id: str = Field(
        default=...,
        description=(
            "Bucket ID of the internal staging bucket of the local data hub's S3 system"
            "where the encrypted files are uploaded to."
        ),
    )
    credentials: NoEndpointURLS3Config


class S3ObjectStoragesConfig(BaseSettings):
    """Custom implementation of the corresponding service commons class to initialize with empty URLs"""

    object_storages: dict[str, S3ObjectStorageNodeConfig]


class LegacyConfig(S3ObjectStoragesConfig):
    """Required options for legacy file uploads."""

    part_size: int = Field(
        default=16, description="Upload part size in MiB. Has to be between 5 and 5120."
    )
    output_dir: Path = Field(
        default=...,
        description=(
            "Directory for the output metadata files. For each file upload one metadata"
            + " file in yaml format will be generated. It contains details on the files"
            + " such as checksums, the original file path, the auto generated object ID"
            + " used on the S3 system, and the ID of the secret (the secret itself is"
            + " automatically communicated to GHGA Central) used to encrypt the file."
        ),
    )
    selected_storage_alias: str = Field(
        default=...,
        description=(
            "Alias of the selected storage node/location. Has to match the backend configuration"
            + " and must also be present in the local storage configuration."
            + " During the later ingest phase, the alias will be validated by the File Ingest Service."
        ),
    )
    wkvs_api_url: str = Field(
        default="https://data.ghga.de/.well-known",
        description="URL to the root of the WKVS API. Should start with https://.",
    )
    client_exponential_backoff_max: NonNegativeInt = Field(
        default=60,
        description="Maximum number of seconds to wait for when using exponential backoff retry strategies.",
    )
    client_retry_status_codes: list[int] = Field(default=[408, 500, 502, 503, 504])
    client_timeout: NonNegativeInt | None = Field(
        default=60, description="Timeout for client requests in seconds"
    )
    client_max_parallel_transfers: PositiveInt = Field(
        default=10,
        description="Maximum number of ongoing concurrent part uploads or downloads.",
    )
    client_num_retries: NonNegativeInt = Field(
        default=5,
        description="Number of times a request should be retried on non critical errors.",
    )

    @field_validator("output_dir")
    def expand_env_vars_output_dir(cls, output_dir: Path):  # noqa: N805
        """Expand vars in path"""
        return expand_env_vars_in_path(output_dir)


class Config(LegacyConfig):
    """Required options for file uploads."""

    secret_ingest_pubkey: str = Field(
        default=...,
        description=(
            "Public key provided by GHGA Central used to encrypt the communication with"
            + " GHGA Central."
        ),
    )
    secret_ingest_baseurl: str = Field(
        default=...,
        description=(
            "Base URL under which the /ingest_secret endpoint is available."
            + " This is an endpoint exposed by GHGA Central. This value is provided by"
            + " GHGA Central on demand."
        ),
    )
