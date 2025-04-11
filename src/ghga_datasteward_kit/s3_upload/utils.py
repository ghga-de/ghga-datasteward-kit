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
"""Helper functions used across different modules in the s3_upload package."""

import logging
import math
import sys
from collections.abc import Iterator
from io import BufferedReader
from pathlib import Path

import crypt4gh.lib
import httpx
from hexkit.providers.s3 import S3Config, S3ObjectStorage

from ghga_datasteward_kit.s3_upload.config import LegacyConfig
from ghga_datasteward_kit.utils import path_join

LOG = logging.getLogger("s3_upload")


def read_file_parts(
    file: BufferedReader, *, part_size: int, from_part: int = 1
) -> Iterator[bytes]:
    """
    Returns an iterator to iterate through file parts of the given size (in bytes).

    By default it start with the first part but you may also start from a specific part
    in the middle of the file using the `from_part` argument. This might be useful to
    resume an interrupted reading process.

    Please note: opening and closing of the file MUST happen outside of this function.
    """
    initial_offset = part_size * (from_part - 1)
    file.seek(initial_offset)

    while True:
        file_part = file.read(part_size)

        if len(file_part) == 0:
            return

        yield file_part


def get_bucket_id(config: LegacyConfig):
    """Get configured bucket ID for the selected storage"""
    storage_alias = config.selected_storage_alias

    try:
        storage_config = config.object_storages[storage_alias]
    except KeyError as error:
        raise ValueError(
            f"No storage configured for the given alias {storage_alias}."
        ) from error

    return storage_config.bucket_id


def get_object_storage(config: LegacyConfig):
    """Configure S3 and return S3 DAO"""
    storage_alias = config.selected_storage_alias
    storage_endpoint_map = retrieve_endpoint_urls(config)

    # fetch correct config
    try:
        endpoint_url = storage_endpoint_map[storage_alias]
        storage_config = config.object_storages[storage_alias]
    except KeyError as error:
        raise ValueError(
            f"No storage configured for the given alias {storage_alias}."
        ) from error

    s3_config = S3Config(
        s3_endpoint_url=endpoint_url,
        s3_access_key_id=storage_config.credentials.s3_access_key_id.get_secret_value(),
        s3_secret_access_key=storage_config.credentials.s3_secret_access_key.get_secret_value(),  # type: ignore
        s3_session_token=None,
        aws_config_ini=None,
    )
    return S3ObjectStorage(config=s3_config)


def retrieve_endpoint_urls(config: LegacyConfig, value_name: str = "storage_aliases"):
    """Get S3 endpoint URLS from WKVS"""
    url = path_join(config.wkvs_api_url, "values", value_name)

    try:
        response = httpx.get(url)
    except httpx.RequestError:
        LOG.error(f"Could not retrieve data from {url} due to connection issues.")
        raise

    status_code = response.status_code
    if status_code != 200:
        raise ValueError(f"Received unexpected response code {status_code} from {url}.")
    try:
        return response.json()[value_name]
    except KeyError as err:
        raise ValueError(
            f"Response from {url} did not include expected field '{value_name}'"
        ) from err


def get_segments(part: bytes, segment_size: int):
    """Chunk part into cipher segments"""
    full_segments = len(part) // segment_size
    segments = [
        part[i * segment_size : (i + 1) * segment_size] for i in range(full_segments)
    ]
    # get potential remainder of bytes that we need to handle
    # for non-matching boundaries between part and cipher segment size
    incomplete_segment = part[full_segments * segment_size :]
    return segments, incomplete_segment


def get_ranges(file_size: int, part_size: int):
    """Calculate part ranges"""
    num_parts = file_size // part_size
    byte_ranges = [
        (part_size * part_no, part_size * (part_no + 1) - 1)
        for part_no in range(num_parts)
    ]
    if part_size * num_parts != file_size:
        byte_ranges.append((part_size * num_parts, file_size - 1))
    return byte_ranges


def handle_superficial_error(msg: str):
    """Don't want user dealing with stacktrace on simple input/output issues, log instead"""
    LOG.critical(msg)
    sys.exit(-1)


def check_adjust_part_size(config: LegacyConfig, file_size: int):
    """
    Convert specified part size from MiB to bytes, check if it needs adjustment and
    adjust accordingly
    """
    lower_bound = 5 * 1024**2
    upper_bound = 5 * 1024**3
    part_size = config.part_size * 1024**2

    # clamp user input part sizes
    if part_size < lower_bound:
        part_size = lower_bound
    elif part_size > upper_bound:
        part_size = upper_bound

    # fixed list for now, maybe change to something more meaningful
    sizes_mib = [2**x for x in range(3, 13)]
    sizes = [size * 1024**2 for size in sizes_mib]

    # encryption will cause growth of ~ 0.0427%, so assume we might
    # need five more parts for this check
    if file_size / part_size > 9_995:
        for candidate_size in sizes:
            if candidate_size > part_size and file_size / candidate_size <= 9_995:
                part_size = candidate_size
                break
        else:
            raise ValueError(
                "Could not find a valid part size that would allow to upload all file parts"
            )

    if part_size != config.part_size * 1024**2:
        LOG.info(
            "Part size was adjusted from %iMiB to %iMiB.\nThe configured part size would either have yielded more than the supported 10.000 parts or was not within the expected bounds (5MiB <= part_size <= 5GiB).",
            config.part_size,
            part_size / 1024**2,
        )

    # need to set this either way as we convert MiB to bytes
    config.part_size = part_size


def check_output_path(output_path: Path):
    """Check if we accidentally try to overwrite an already existing metadata file"""
    if output_path.exists():
        msg = f"Output file {
            output_path.resolve()
        } already exists and cannot be overwritten."
        handle_superficial_error(msg=msg)


def get_encrypted_file_size_and_num_parts(
    *, unencrypted_file_size: int, part_size: int
) -> tuple[int, int]:
    """Calculate encrypted file size and number of parts."""
    num_segments = math.ceil(unencrypted_file_size / crypt4gh.lib.SEGMENT_SIZE)
    encrypted_file_size = unencrypted_file_size + num_segments * 28
    num_parts = math.ceil(encrypted_file_size / part_size)
    return encrypted_file_size, num_parts
