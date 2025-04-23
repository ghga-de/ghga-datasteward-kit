#!/usr/bin/env python3
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

"""A script to translate a OTP tsv into upload jobs."""

import logging
import subprocess  # nosec
import sys
from copy import copy
from pathlib import Path
from time import sleep

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


class BatchUploadManager:
    """Class that manages batch uploads, retries, and associated logging."""

    def __init__(  # noqa: PLR0913
        self,
        config_path: Path,
        output_dir: Path,
        parallel_processes: int,
        dry_run: bool,
        legacy_mode: bool,
        max_retries: int | None = None,
    ):
        """Initialize the instance with required attributes."""
        self.config_path = config_path
        self.output_dir = output_dir
        self.parallel_processes = parallel_processes
        self.dry_run = dry_run
        self.legacy_mode = legacy_mode
        self.max_retries = max_retries
        self.files_failed: list[FileMetadata] = []
        self.files_succeeded: list[FileMetadata] = []
        self.files_skipped: list[FileMetadata] = []
        self.files_to_do: list[FileMetadata] = []
        self.in_progress: dict[FileMetadata, subprocess.Popen] = {}

    def trigger_file_upload(self, file: FileMetadata) -> subprocess.Popen | None:
        """
        Checks whether the file was already uploaded, if not, the upload is triggered
        in a separate process and the corresponding subprocess.Popen object is returned.
        """
        if check_file_upload(file=file, output_dir=self.output_dir):
            logging.info("File '%s' has already been uploaded: skipping.", file.alias)
            return None

        command_line = prepare_upload_command_line(
            file=file,
            output_dir=self.output_dir,
            config_path=self.config_path,
            legacy_mode=self.legacy_mode,
        )

        if self.dry_run:
            logging.info("Would execute: %s", command_line)
            return None

        logging.info("The upload of the file with alias '%s' has started.", file.alias)
        return subprocess.Popen(  # noqa: S602
            command_line,
            shell=True,
            executable="/bin/bash",
        )

    def _start_next_file(self):
        next_file = self.files_to_do[-1]
        process = self.trigger_file_upload(file=next_file)
        if process:
            self.in_progress[next_file] = process
            self.files_to_do.pop()
        else:
            self.files_skipped.append(next_file)

    def _poll_uploads(self):
        """Check ongoing uploads. Log and remove completed or errored uploads."""
        for file, process in copy(self.in_progress).items():
            status = process.poll()

            # If file upload is ongoing, just continue
            if status is None:
                continue

            if status == 0 and check_file_upload(file=file, output_dir=self.output_dir):
                logging.info("Successfully uploaded file with alias '%s'.", file.alias)
                self.files_succeeded.append(file)
            else:
                logging.error("Failed to upload file with alias '%s'.", file.alias)
                self.files_failed.append(file)

            del self.in_progress[file]

    def handle_file_uploads(self, files: list[FileMetadata]):
        """Handles the upload of multiple files in parallel."""
        self.files_to_do = copy(files)
        self.files_to_do.reverse()

        # Outer `try` only exists to execute `finally`
        while self.files_to_do or self.in_progress:
            try:
                # start new processes:
                while (
                    len(self.in_progress) < self.parallel_processes and self.files_to_do
                ):
                    self._start_next_file()

                # check status of uploads in progress:
                self._poll_uploads()

                # Sleep briefly before polling uploads again or starting new uploads
                if not self.dry_run:
                    sleep(2)
            except:
                if self.max_retries is None:
                    logging.warning("Error encountered during file upload, retrying.")
                elif self.max_retries > 0:
                    self.max_retries -= 1
                else:
                    logging.error("Error during file upload")
                    self._log_upload_stats()
                    for _, process in self.in_progress.items():
                        process.terminate()
                    raise
        self._log_upload_stats()

    def _log_upload_stats(self):
        logging.info(
            "Finished with %s successful and %s failed uploads. %s were skipped.",
            str(len(self.files_succeeded)),
            str(len(self.files_failed)),
            str(len(self.files_skipped)),
        )
        logging.info(
            "The files with following aliases failed: "
            + ", ".join([file.alias for file in self.files_failed])
        )


def main(  # noqa: PLR0913
    file_overview_tsv: Path,
    config_path: Path,
    parallel_processes: int,
    dry_run: bool,
    legacy_mode: bool,
    max_retries: int | None = None,
):
    """
    Custom script to encrypt data using Crypt4GH and directly uploading it to S3
    objectstorage.
    """
    config_class: type[LegacyConfig | Config] = LegacyConfig if legacy_mode else Config
    config = load_config_yaml(path=config_path, config_cls=config_class)
    files = load_file_metadata(file_overview_tsv=file_overview_tsv)

    batch_upload_manager = BatchUploadManager(
        config_path=config_path,
        output_dir=config.output_dir,
        dry_run=dry_run,
        legacy_mode=legacy_mode,
        max_retries=max_retries,
        parallel_processes=parallel_processes,
    )

    batch_upload_manager.handle_file_uploads(files=files)
