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
#
"""S3 upload specific configuration."""

import subprocess  # nosec
from pathlib import Path

from pydantic import BaseSettings, Field, SecretStr, validator


def expand_env_vars_in_path(path: Path) -> Path:
    """Expand environment variables in a Path."""

    with subprocess.Popen(  # nosec
        f"realpath {path}", shell=True, stdout=subprocess.PIPE
    ) as process:
        if process.wait() != 0 or not process.stdout:
            raise RuntimeError(f"Parsing of path failed: {path}")

        output = process.stdout.read().decode("utf-8").strip()

    return Path(output)


class LegacyConfig(BaseSettings):
    """
    Required options for legacy file uploads.
    """

    s3_endpoint_url: SecretStr = Field(..., description="URL of the S3 server")
    s3_access_key_id: SecretStr = Field(
        ..., description="Access key ID for the S3 server"
    )
    s3_secret_access_key: SecretStr = Field(
        ..., description="Secret access key for the S3 server"
    )
    bucket_id: str = Field(
        ..., description="Bucket id where the encrypted, uploaded file is stored"
    )
    part_size: int = Field(
        16, description="Upload part size in MiB. Has to be between 5 and 5120."
    )
    output_dir: Path = Field(
        ...,
        description="Directory for the output metadata file",
    )

    @validator("output_dir")
    def expand_env_vars_output_dir(
        cls, output_dir: Path
    ):  # pylint: disable=no-self-argument
        """Expand vars in path"""
        return expand_env_vars_in_path(output_dir)


class Config(LegacyConfig):
    """
    Required options for file uploads.
    """

    secret_ingest_pubkey: str = Field(
        ..., description="Public key used for encryption of the payload."
    )
    secret_ingest_url: str = Field(
        ...,
        description="Base URL under which the /ingest_secret endpoint is available.",
    )
