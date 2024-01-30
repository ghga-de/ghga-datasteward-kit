#!/usr/bin/env python3
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

"""A script to translate a OTP tsv into upload jobs."""

import logging
import subprocess  # nosec
import sys
from copy import copy
from pathlib import Path
from time import sleep
from typing import Optional, Union

from pydantic import BaseModel

from ghga_datasteward_kit.s3_upload import Config, LegacyConfig, load_config_yaml

HERE = Path(__file__).parent


class FileMetadata(BaseModel):
    """Container for storing metadata on files that shall be uploaded."""

    path: Path
    alias: str

    class Config:
        """Pydantic-specific configuration."""

        frozen = True


def load_file_metadata(file_overview_tsv: Path) -> list[FileMetadata]:
    """Load file metadata from a tsv."""
    with open(file_overview_tsv, encoding="utf-8") as tsv_file:
        files = [
            FileMetadata(
                path=Path(line.split("\t")[0].strip()).resolve(),
                alias=line.split("\t")[1].strip(),
            )
            for line in tsv_file.readlines()
            if line != ""
        ]

    non_existing_files = [file for file in files if not file.path.exists()]
    if non_existing_files:
        raise RuntimeError(
            "The following paths do not exist:\n"
            + "\n".join([str(file.path) for file in non_existing_files])
        )

    return files


def check_file_upload(file: FileMetadata, output_dir: Path) -> bool:
    """Returns true if the file was already uploaded. Returns false otherwise."""
    output_yaml = output_dir / f"{file.alias}.json"
    return output_yaml.exists()


def prepare_upload_command_line(
    file: FileMetadata, output_dir: Path, config_path: Path, legacy_mode: bool
) -> str:
    """Returns a command line for uploading the specified file."""
    log_file_path = output_dir / f"{file.alias}.log"
    python_interpreter_path = Path(sys.executable)

    subcommand = "legacy-upload" if legacy_mode else "upload"

    return (
        f"{python_interpreter_path} -m ghga_datasteward_kit files {subcommand}"
        + f" --input-path {file.path}"
        + f" --alias {file.alias} --config-path {config_path}"
        + f" > {log_file_path} 2>&1"
    )


def trigger_file_upload(
    file: FileMetadata,
    output_dir: Path,
    config_path: Path,
    dry_run: bool,
    legacy_mode: bool,
) -> Optional[subprocess.Popen]:
    """
    Checks whether the file was already uploaded, if not, the upload is triggered
    in a separate process and the corresponding subprocess.Popen object is returned.
    """
    if check_file_upload(file=file, output_dir=output_dir):
        logging.info("File '%s' has already been uploaded: skipping.", file.alias)
        return None

    command_line = prepare_upload_command_line(
        file=file,
        output_dir=output_dir,
        config_path=config_path,
        legacy_mode=legacy_mode,
    )

    if dry_run:
        logging.info("Would execute: %s", command_line)
        return None

    logging.info("The upload of the file with alias '%s' has started.", file.alias)
    return subprocess.Popen(
        command_line,
        shell=True,  # noqa: S602
        executable="/bin/bash",
    )


def handle_file_uploads(  # noqa: PLR0913, PLR0912
    files: list[FileMetadata],
    output_dir: Path,
    config_path: Path,
    parallel_processes: int,
    dry_run: bool,
    legacy_mode: bool,
):
    """Handles the upload of multiple files in parallel."""
    files_to_do = copy(files)
    files_to_do.reverse()
    in_progress: dict[FileMetadata, subprocess.Popen] = {}
    files_failed: list[FileMetadata] = []
    files_succeeded: list[FileMetadata] = []
    files_skipped: list[FileMetadata] = []

    try:
        while files_to_do or in_progress:
            # start new processes:
            while len(in_progress) < parallel_processes and files_to_do:
                next_file = files_to_do.pop()
                process = trigger_file_upload(
                    file=next_file,
                    output_dir=output_dir,
                    config_path=config_path,
                    dry_run=dry_run,
                    legacy_mode=legacy_mode,
                )

                if process:
                    in_progress[next_file] = process
                else:
                    files_skipped.append(next_file)

            # check status of uploads in progress:
            for file, process in copy(in_progress).items():
                status = process.poll()

                if status is None:
                    continue

                if status == 0 and check_file_upload(file=file, output_dir=output_dir):
                    logging.info(
                        "Successfully uploaded file with alias '%s'.", file.alias
                    )
                    files_succeeded.append(file)
                else:
                    logging.error("Failed to upload file with alias '%s'.", file.alias)
                    files_failed.append(file)

                del in_progress[file]

            if not dry_run:
                sleep(2)
    except:
        for _, process in in_progress.items():
            process.terminate()
        raise
    finally:
        logging.info(
            "Finished with %s successful and %s failed uploads. %s were skipped.",
            str(len(files_succeeded)),
            str(len(files_failed)),
            str(len(files_skipped)),
        )
        logging.info(
            "The files with following aliases failed: "
            + ", ".join([file.alias for file in files_failed])
        )


def main(
    file_overview_tsv: Path,
    config_path: Path,
    parallel_processes: int,
    dry_run: bool,
    legacy_mode: bool,
):
    """
    Custom script to encrypt data using Crypt4GH and directly uploading it to S3
    objectstorage.
    """
    config_class: type[Union[LegacyConfig, Config]] = (
        LegacyConfig if legacy_mode else Config
    )
    config = load_config_yaml(path=config_path, config_cls=config_class)
    files = load_file_metadata(file_overview_tsv=file_overview_tsv)

    handle_file_uploads(
        files=files,
        output_dir=config.output_dir,
        config_path=config_path,
        parallel_processes=parallel_processes,
        dry_run=dry_run,
        legacy_mode=legacy_mode,
    )
