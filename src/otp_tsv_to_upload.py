#!/usr/bin/env python3
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

"""A script to translate a OTP tsv into upload jobs."""

import logging
from pathlib import Path

import typer
from pydantic import BaseModel

from .s3_upload import load_config_yaml


class FileMetadata(BaseModel):
    """Container for storing metadata on files that shall be uploaded."""

    path: Path
    alias: str


def load_file_metadata(otp_tsv: Path) -> list[FileMetadata]:
    """Load file metadata from a tsv."""

    with open(otp_tsv, "r", encoding="utf-8") as tsv_file:
        lines = [line for line in tsv_file.readlines()]


def main(
    otp_tsv: Path = typer.Argument(..., help="Path to OTP tsv file."),
    config: Path = typer.Argument(..., help=("Path to a config YAML.")),
):
    """
    Custom script to encrypt data using Crypt4GH and directly uploading it to S3
    objectstorage.
    """

    config_obj = load_config_yaml(config)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    typer.run(main)
