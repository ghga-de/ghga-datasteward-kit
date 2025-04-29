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
        self.retries_remaining = max_retries
        self.files_failed: list[FileMetadata] = []
        self.files_succeeded: list[FileMetadata] = []
        self.files_skipped: list[FileMetadata] = []
        self.files_to_do: list[FileMetadata] = []
        self.in_progress: dict[FileMetadata, subprocess.Popen] = {}

    def handle_file_uploads(self, files: list[FileMetadata]):
        """Handles the upload of multiple files in parallel."""
        self.files_to_do = copy(files)
        self.files_to_do.reverse()

        # The outer while loop runs while there is still any work to do
        while self.files_to_do or self.in_progress:
            try:
                # Kick off as many file uploads in parallel as possible until none remain
                while (
                    len(self.in_progress) < self.parallel_processes and self.files_to_do
                ):
                    self._start_next_file()

                # check status of uploads in progress:
                self._poll_uploads()
            except Exception:
                # If an error occurs, either retry while allowed or log the stats and
                #  terminate any running upload processes before re-raising.
                logging.error(
                    "Unhandled error during file upload, canceling in-progress uploads."
                )
                # Cancel in-progress uploads and list them as failed
                for file, process in self.in_progress.items():
                    try:
                        # Attempt to do one last check for completed uploads
                        status = process.poll()
                        if status == 0 and check_file_upload(
                            file=file, output_dir=self.output_dir
                        ):
                            self.files_succeeded.append(file)
                        else:
                            self.files_failed.append(file)
                    finally:
                        process.terminate()
                        del self.in_progress[file]

                # If able, immediately retry any failed files. Otherwise, re-raise.
                self._log_upload_stats()
                if (self.files_failed or self.files_to_do) and self._redeem_retry():
                    self._retry_failed()
                else:
                    raise
            # Sleep briefly before polling uploads again or starting new uploads
            #  The sleep is placed here so that there is still a pause between retries
            if not self.dry_run:
                sleep(2)

        # If reaching this point, the batch was finished without unhandled errors.
        #  There might have been files that failed, however. If that's the case, retry.
        self._log_upload_stats()
        if (self.files_failed or self.files_to_do) and self._redeem_retry():
            self._retry_failed()

    def _start_next_file(self):
        """Triggers a file upload process for the next file and tracks the process.

        If an error occurs during the call to `trigger_file_upload`, the file will
        be placed in the list of failed files.
        """
        next_file = self.files_to_do.pop()
        try:
            process = self.trigger_file_upload(file=next_file)
        except:
            self.files_failed.append(next_file)
        else:
            if process:
                self.in_progress[next_file] = process
            else:
                self.files_skipped.append(next_file)

    def trigger_file_upload(self, file: FileMetadata) -> subprocess.Popen | None:
        """
        Checks whether the file was already uploaded, if not, the upload is triggered
        in a separate process and the corresponding subprocess.

        Popen object is returned.
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

    def _redeem_retry(self) -> bool:
        """Returns True if allowed to retry, else False.

        If `retries_remaining` is `None`, infinite retries are allowed.
        Otherwise, `retries_remaining` is decremented by 1.
        """
        if self.retries_remaining is None:
            return True

        if self.retries_remaining > 0:
            self.retries_remaining -= 1
            return True
        return False

    def _retry_failed(self):
        """Retry upload process but only attempt the failed files from a previous run"""
        logging.info("Retrying failed and/or remaining files...")
        self.files_to_do.extend(reversed(self.files_failed))
        self.files_failed.clear()
        sleep(2)
        new_file_list = list(reversed(self.files_to_do))
        self.handle_file_uploads(new_file_list)

    def _log_upload_stats(self):
        succeeded = len(self.files_succeeded)
        failed = len(self.files_failed)
        skipped = len(self.files_skipped)
        processed = succeeded + failed + skipped
        remaining = len(self.files_to_do)
        total = processed + remaining
        verb = "was" if skipped == 1 else "were"
        logging.info(f"Finished processing {total} files:")
        logging.info(
            f"  {succeeded} succeeded, {failed} failed, and {skipped} {verb} skipped."
        )
        if remaining:
            logging.info(
                f"  {remaining} file(s) remain to be uploaded, including failures."
            )
        if self.files_failed:
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
    object storage.
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
