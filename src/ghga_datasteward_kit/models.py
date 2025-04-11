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
"""Contains different output metadata representations"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ghga_service_commons.utils.crypt import encrypt
from pydantic import BaseModel

LOG = logging.getLogger(__name__)


class Checksums:
    """Container for checksum calculation"""

    def __init__(self):
        self.unencrypted_sha256 = hashlib.sha256()
        self.encrypted_md5: list[str] = []
        self.encrypted_sha256: list[str] = []

    def __repr__(self) -> str:
        """Returns a human readable representation of the Checksums object."""
        return (
            f"Unencrypted: {self.unencrypted_sha256.hexdigest()}\n"
            + f"Encrypted MD5: {self.encrypted_md5}\n"
            + f"Encrypted SHA256: {self.encrypted_sha256}"
        )

    def get(self):
        """Return all checksums at the end of processing"""
        return (
            self.unencrypted_sha256.hexdigest(),
            self.encrypted_md5,
            self.encrypted_sha256,
        )

    def update_unencrypted(self, part: bytes):
        """Update checksum for unencrypted file"""
        self.unencrypted_sha256.update(part)

    def update_encrypted(self, part: bytes):
        """Update encrypted part checksums"""
        self.encrypted_md5.append(hashlib.md5(part, usedforsecurity=False).hexdigest())
        self.encrypted_sha256.append(hashlib.sha256(part).hexdigest())


class EncryptedPayload(BaseModel):
    """Contains encrypted upload metadata or secret as payload"""

    payload: str


class MetadataBase(BaseModel):
    """Common base for all output and upload models"""

    file_id: str
    bucket_id: str
    object_id: str
    part_size: int
    unencrypted_size: int
    encrypted_size: int
    unencrypted_checksum: str
    encrypted_md5_checksums: list[str]
    encrypted_sha256_checksums: list[str]
    storage_alias: str

    def prepare_output(self) -> dict[str, str]:
        """Prepare shared fields for output"""
        output: dict[str, Any] = {}

        output["Bucket ID"] = self.bucket_id
        output["File UUID"] = self.file_id
        output["Part Size"] = f"{self.part_size // 1024**2} MiB"
        output["Unencrypted file size"] = self.unencrypted_size
        output["Encrypted file size"] = self.encrypted_size
        output["Unencrypted file checksum"] = self.unencrypted_checksum
        output["Encrypted file part checksums (MD5)"] = self.encrypted_md5_checksums
        output["Encrypted file part checksums (SHA256)"] = (
            self.encrypted_sha256_checksums
        )
        output["Storage alias"] = self.storage_alias

        return output


class Metadata(MetadataBase):
    """Current upload model"""

    secret_id: str


class OutputMetadata(Metadata):
    """Current output metadata model with (de)serialization logic"""

    alias: str
    original_path: Path

    def serialize(self, output_path: Path):
        """Serialize metadata to file"""
        output = self.prepare_output()

        output["Alias"] = self.alias
        output["Original filesystem path"] = str(self.original_path.resolve())
        output["Symmetric file encryption secret ID"] = self.secret_id

        if not output_path.parent.exists():
            output_path.parent.mkdir(parents=True)

        # owner read-only
        with output_path.open("w") as file:
            json.dump(output, file, indent=2)
        os.chmod(path=output_path, mode=0o400)

    @classmethod
    def load(cls, input_path: Path, selected_alias: str, fallback_bucket: str):
        """Load metadata from serialized file"""
        with input_path.open("r") as infile:
            data = json.load(infile)

        # Support for older file uploads without explicit storage alias or bucket id
        # Ingest the configured selected alias if none can be found in the metadata
        try:
            storage_alias = data["Storage alias"]
        except KeyError:
            LOG.warning(
                "Could not find storage alias in metadata, populating with configured alias '%s' instead.",
                selected_alias,
            )
            storage_alias = selected_alias
        try:
            bucket_id = data["Bucket ID"]
        except KeyError:
            LOG.warning(
                "Could not find bucket ID in metadata, populating with configured bucket '%s' instead.",
                fallback_bucket,
            )
            bucket_id = fallback_bucket

        file_id = data["File UUID"]
        part_size = int(data["Part Size"].rpartition(" MiB")[0]) * 1024**2

        return OutputMetadata(
            alias=data["Alias"],
            original_path=data["Original filesystem path"],
            file_id=file_id,
            bucket_id=bucket_id,
            object_id=file_id,
            part_size=part_size,
            secret_id=data["Symmetric file encryption secret ID"],
            unencrypted_checksum=data["Unencrypted file checksum"],
            encrypted_md5_checksums=data["Encrypted file part checksums (MD5)"],
            encrypted_sha256_checksums=data["Encrypted file part checksums (SHA256)"],
            unencrypted_size=int(data["Unencrypted file size"]),
            encrypted_size=int(data["Encrypted file size"]),
            storage_alias=storage_alias,
        )

    def to_upload_metadata(self, file_id: str):
        """Convert internal output file representation to request model"""
        return Metadata(
            file_id=file_id,
            bucket_id=self.bucket_id,
            object_id=self.object_id,
            part_size=self.part_size,
            unencrypted_size=self.unencrypted_size,
            encrypted_size=self.encrypted_size,
            secret_id=self.secret_id,
            unencrypted_checksum=self.unencrypted_checksum,
            encrypted_md5_checksums=self.encrypted_md5_checksums,
            encrypted_sha256_checksums=self.encrypted_sha256_checksums,
            storage_alias=self.storage_alias,
        )


class LegacyMetadata(MetadataBase):
    """Legacy upload model"""

    file_secret: str

    def encrypt_metadata(self, public_key: str) -> EncryptedPayload:
        """Create payload by encryption FileUploadMetadata"""
        payload = self.model_dump_json()
        encrypted = encrypt(data=payload, key=public_key)

        return EncryptedPayload(payload=encrypted)


class LegacyOutputMetadata(LegacyMetadata):
    """Legacy output metadata model with (de)serialization logic"""

    alias: str
    original_path: Path

    def serialize(self, output_path: Path):
        """Serialize metadata to file"""
        output = self.prepare_output()

        output["Alias"] = self.alias
        output["Original filesystem path"] = str(self.original_path.resolve())
        output["Symmetric file encryption secret"] = self.file_secret

        if not output_path.parent.exists():
            output_path.parent.mkdir(parents=True)

        # owner read-only
        with output_path.open("w") as file:
            json.dump(output, file, indent=2)
        os.chmod(path=output_path, mode=0o400)

    @classmethod
    def load(cls, input_path: Path, selected_alias: str, fallback_bucket: str):
        """Load metadata from serialized file"""
        with input_path.open("r") as infile:
            data = json.load(infile)

        # Support for older file uploads without explicit storage alias or bucket id
        # Ingest the configured selected alias if none can be found in the metadata
        try:
            storage_alias = data["Storage alias"]
        except KeyError:
            LOG.warning(
                "Could not find storage alias in metadata, populating with configured alias '%s' instead.",
                selected_alias,
            )
            storage_alias = selected_alias
        try:
            bucket_id = data["Bucket ID"]
        except KeyError:
            LOG.warning(
                "Could not find bucket ID in metadata, populating with configured bucket '%s' instead.",
                fallback_bucket,
            )
            bucket_id = fallback_bucket

        file_id = data["File UUID"]
        part_size = int(data["Part Size"].rpartition(" MiB")[0]) * 1024**2

        return LegacyOutputMetadata(
            alias=data["Alias"],
            original_path=data["Original filesystem path"],
            file_id=file_id,
            bucket_id=bucket_id,
            object_id=file_id,
            part_size=part_size,
            file_secret=data["Symmetric file encryption secret"],
            unencrypted_checksum=data["Unencrypted file checksum"],
            encrypted_md5_checksums=data["Encrypted file part checksums (MD5)"],
            encrypted_sha256_checksums=data["Encrypted file part checksums (SHA256)"],
            unencrypted_size=int(data["Unencrypted file size"]),
            encrypted_size=int(data["Encrypted file size"]),
            storage_alias=storage_alias,
        )

    def to_upload_metadata(self, file_id: str):
        """Convert internal output file representation to request model"""
        return LegacyMetadata(
            file_id=file_id,
            bucket_id=self.bucket_id,
            object_id=self.object_id,
            part_size=self.part_size,
            unencrypted_size=self.unencrypted_size,
            encrypted_size=self.encrypted_size,
            file_secret=self.file_secret,
            unencrypted_checksum=self.unencrypted_checksum,
            encrypted_md5_checksums=self.encrypted_md5_checksums,
            encrypted_sha256_checksums=self.encrypted_sha256_checksums,
            storage_alias=self.storage_alias,
        )


@dataclass
class UploadParameters:
    """Contains information needed by the uploader class within a multipart upload."""

    bucket_id: str
    file_id: str
    upload_id: str
    num_parts: int
