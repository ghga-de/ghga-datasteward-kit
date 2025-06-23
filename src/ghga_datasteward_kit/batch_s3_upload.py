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
from time import monotonic, sleep

from pydantic import BaseModel

from ghga_datasteward_kit.s3_upload import Config, LegacyConfig, load_config_yaml

HERE = Path(__file__).parent
SEC_IN_HOUR = 60 * 60  # seconds in an hour
SEC_IN_DAY = 24 * SEC_IN_HOUR  # seconds in a day


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

    # Check if the file paths exist
    non_existing_files = [
        file for file in files if not (file.path.is_file() and file.path.exists())
    ]
    if non_existing_files:
        raise RuntimeError(
            "The following paths do not exist or are not files:\n"
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

        # Values to help calculate estimated time remaining
        self.total_initial_bytes: int = 0
        self.file_start_times: dict[FileMetadata, float] = {}
        self.latest_upload_rate_bps: int = 0
        self.batch_size: int = 0
        self.file_sizes: dict[FileMetadata, int] = {}
        self.total_bytes_processed: int = 0

    def _initialize_stats(self, files: list[FileMetadata]):
        """Record the sizes of files to be uploaded.

        Does not reset upload speed or file sizes since those can be reused
        from previous runs.
        """
        self.files_failed.clear()
        self.files_succeeded.clear()
        self.files_skipped.clear()
        self.total_initial_bytes = 0
        self.total_bytes_processed = 0
        self.batch_size = len(files)
        for file_metadata in files:
            if file_metadata not in self.file_sizes:
                # Get file size. Existence as a file is checked in `load_file_metadata`
                self.file_sizes[file_metadata] = file_metadata.path.stat().st_size
            self.total_initial_bytes += self.file_sizes[file_metadata]

    def handle_file_uploads(self, files: list[FileMetadata]):
        """Handles the upload of multiple files in parallel."""
        self.files_to_do = copy(files)
        self.files_to_do.reverse()

        # Populate file sizes and total initial bytes
        self._initialize_stats(self.files_to_do)

        print(
            f"\nStarting batch upload - {len(files)} files totaling {self._format_bytes(self.total_initial_bytes)}"
        )
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
                self.in_progress.clear()  # Clear in-progress uploads

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

    def trigger_file_upload(self, file: FileMetadata) -> subprocess.Popen | None:
        """
        Checks whether the file was already uploaded, if not, the upload is triggered
        in a separate process and the corresponding subprocess.

        Popen object is returned.
        """
        if check_file_upload(file=file, output_dir=self.output_dir):
            logging.info("File '%s' has already been uploaded: skipping.", file.alias)
            self.files_skipped.append(file)
            self._print_upload_progress(file, success=True, skipped=True)
            return None
        self.file_start_times[file] = monotonic()

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

    def _format_time(self, seconds: int) -> str:
        """Formats seconds into a '00d 00h 00m' string."""
        if seconds == 0:
            return "00d 00h 00m"

        # Calculate days, hours, and minutes
        days, remaining_seconds_after_days = divmod(seconds, SEC_IN_DAY)
        hours, remaining_seconds_after_hours = divmod(
            remaining_seconds_after_days, SEC_IN_HOUR
        )
        minutes, remaining_seconds_after_minutes = divmod(
            remaining_seconds_after_hours, 60
        )

        if remaining_seconds_after_minutes > 0 and minutes == 0:
            # If there are remaining seconds but no full minutes, we set minutes to 1
            minutes = 1
        return f"{days:02}d {hours:02}h {minutes:02}m"

    def _format_bytes(self, size_bytes: int) -> str:
        """Formats bytes into a human-readable string (B, KB, MB, GB)."""
        if size_bytes == 0:
            return "0 B"
        suffixes = ["B", "KB", "MB", "GB", "TB", "PB"]
        power = 0
        # Determine the appropriate suffix by dividing by 1024
        num = float(size_bytes)
        while num >= 1024 and power < len(suffixes) - 1:
            num /= 1024
            power += 1
        return f"{num:.2f} {suffixes[power]}"

    def _calculate_eta(self, file: FileMetadata, recalc_speed: bool) -> str:
        """Calculate the estimated time remaining for the batch.

        ETA is updated after each completed file upload.
        If `recalc_speed` is True, the upload rate is recalculated and stored.
        If `recalc_speed` is False, the previously stored upload rate is used.
        """
        # Get time elapsed since the file upload started
        file_size = self.file_sizes.get(file, 0)

        # Update total bytes processed
        self.total_bytes_processed += file_size

        # If required, update the stored upload rate
        if recalc_speed and self.total_bytes_processed > 0:
            current_time = monotonic()
            upload_duration = max(current_time - self.file_start_times.get(file, 1), 1)
            # Calculate average rate of most recent upload in bytes per second
            self.latest_upload_rate_bps = int(file_size / upload_duration)

        eta = "N/A"

        # If the stored upload rate is available, estimate the remaining time
        if self.latest_upload_rate_bps:
            bytes_left = self.total_initial_bytes - self.total_bytes_processed
            estimated_remaining_seconds = bytes_left // self.latest_upload_rate_bps
            eta = self._format_time(estimated_remaining_seconds)

        return eta

    def _print_upload_progress(
        self, file: FileMetadata, success: bool, skipped: bool = False
    ):
        """Print the upload progress for the batch upon finishing the given file."""
        file_size = self.file_sizes.get(file, 0)
        eta = self._calculate_eta(file, recalc_speed=success and not skipped)
        files_processed = len(
            self.files_succeeded + self.files_failed + self.files_skipped
        )
        fmt_bytes_processed = self._format_bytes(self.total_bytes_processed)
        fmt_total_bytes = self._format_bytes(self.total_initial_bytes)
        symbol = "✓"
        extra_msg = " "
        if skipped:
            symbol = "-"
            extra_msg = " already uploaded "
        elif not success:
            symbol = "✗"
            extra_msg = " failed "

        print(
            f"{symbol} {file.alias}{extra_msg}({self._format_bytes(file_size)})"
            f" ({files_processed}/{self.batch_size} files |"
            f" {fmt_bytes_processed}/{fmt_total_bytes}). ETA: {eta}"
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
                self._print_upload_progress(file, success=True)
            else:
                logging.error("Failed to upload file with alias '%s'.", file.alias)
                self.files_failed.append(file)
                self._print_upload_progress(file, success=False)

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
