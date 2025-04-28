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

"""File related CLI"""

import logging
from pathlib import Path

import typer

from ghga_datasteward_kit import batch_s3_upload, file_deletion, file_ingest, s3_upload

log = logging.getLogger(__name__)

cli = typer.Typer(no_args_is_help=True)


@cli.command(no_args_is_help=True)
def legacy_upload(
    input_path: Path = typer.Option(..., help="Local path of the input file"),
    alias: str = typer.Option(..., help="A human readable file alias"),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
):
    """Upload a single file to S3."""
    s3_upload.legacy_main(input_path=input_path, alias=alias, config_path=config_path)


@cli.command(no_args_is_help=True)
def upload(
    input_path: Path = typer.Option(..., help="Local path of the input file"),
    alias: str = typer.Option(..., help="A human readable file alias"),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
):
    """Upload a single file to S3."""
    s3_upload.main(input_path=input_path, alias=alias, config_path=config_path)


@cli.command(no_args_is_help=True)
def legacy_batch_upload(
    tsv: Path = typer.Option(
        ...,
        help=(
            "Path to a tsv file with the first column containing the file path and the"
            + " second column containing the file alias."
        ),
    ),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
    parallel_processes: int = typer.Option(..., help="Number of parallel uploads."),
    dry_run: bool = typer.Option(
        False,
        help=("Only print commands for each file. No uploads are performed."),
    ),
    max_retries: int | None = typer.Option(
        None, help="Maximum number of automatic retries."
    ),
):
    """Upload multiple files to S3."""
    batch_s3_upload.main(
        file_overview_tsv=tsv,
        config_path=config_path,
        parallel_processes=parallel_processes,
        dry_run=dry_run,
        legacy_mode=True,
        max_retries=max_retries,
    )


@cli.command(no_args_is_help=True)
def batch_upload(
    tsv: Path = typer.Option(
        ...,
        help=(
            "Path to a tsv file with the first column containing the file path and the"
            + " second column containing the file alias."
        ),
    ),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
    parallel_processes: int = typer.Option(..., help="Number of parallel uploads."),
    dry_run: bool = typer.Option(
        False,
        help=("Only print commands for each file. No uploads are performed."),
    ),
    max_retries: int | None = typer.Option(
        None, help="Maximum number of automatic retries."
    ),
):
    """Upload multiple files to S3."""
    batch_s3_upload.main(
        file_overview_tsv=tsv,
        config_path=config_path,
        parallel_processes=parallel_processes,
        dry_run=dry_run,
        legacy_mode=False,
        max_retries=max_retries,
    )


@cli.command(no_args_is_help=True)
def ingest_upload_metadata(
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
):
    """Upload all output metadata files from the given directory to the file ingest service."""
    errors, successes = file_ingest.main(config_path=config_path)

    if errors:
        print(f"Encountered {len(errors)} errors during processing.")
        for file_path, cause in errors.items():
            print(f" -{file_path}: {cause}")
        print("\nSuccessfully ingested the following files:")
        for file_path in sorted(successes):
            print(f" -{file_path}")
    else:
        print("Successfully sent all file upload metadata for ingest.")


@cli.command(no_args_is_help=True)
def delete_file(
    file_id: str = typer.Option(
        ...,
        help=(
            "Public ID of the file for which all associated data across file services should be deleted."
        ),
    ),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
):
    """Call purge controller to remove all data associated with the given file ID from all file services."""
    file_deletion.main(file_id=file_id, config_path=config_path)
