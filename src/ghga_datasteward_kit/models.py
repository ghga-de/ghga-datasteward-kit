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
"""Contains different output metadata representations"""

import base64
import hashlib
import json
import os
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ghga_service_commons.utils.crypt import encrypt
from pydantic import BaseModel


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


class FileUploadMetadataBase(BaseModel):
    """Decrypted payload model for S3 upload script output"""

    # get all data for now, optimize later if we don't need all of it
    file_id: str
    object_id: str
    part_size: int
    unencrypted_size: int
    encrypted_size: int
    unencrypted_checksum: str
    encrypted_md5_checksums: list[str]
    encrypted_sha256_checksums: list[str]

    def encrypt_metadata(self, pubkey: str) -> EncryptedPayload:
        """Create payload by encryption FileUploadMetadata"""
        payload = self.model_dump_json()
        encrypted = encrypt(data=payload, key=pubkey)

        return EncryptedPayload(payload=encrypted)


class LegacyFileUploadMetadata(FileUploadMetadataBase):
    """Decrypted payload model for S3 upload script output"""

    file_secret: str


class FileUploadMetadata(FileUploadMetadataBase):
    """Decrypted payload model for S3 upload script output"""

    secret_id: str


@dataclass
class OutputMetadataBase:
    """Container class for output metadata"""

    alias: str
    file_uuid: str
    original_path: Path
    part_size: int
    unencrypted_checksum: str
    encrypted_md5_checksums: list[str]
    encrypted_sha256_checksums: list[str]
    unencrypted_size: int
    encrypted_size: int

    @abstractmethod
    def to_upload_metadata(self, file_id: str) -> FileUploadMetadataBase:
        """Convert internal output file representation to unencrypted request model"""


@dataclass
class LegacyOutputMetadata(OutputMetadataBase):
    """Container class for output metadata"""

    file_secret: bytes

    def serialize(self, output_path: Path):
        """Serialize metadata to file"""
        output: dict[str, Any] = {}
        output["Alias"] = self.alias
        output["File UUID"] = self.file_uuid
        output["Original filesystem path"] = str(self.original_path.resolve())
        output["Part Size"] = f"{self.part_size // 1024**2} MiB"
        output["Unencrypted file size"] = self.unencrypted_size
        output["Encrypted file size"] = self.encrypted_size
        output["Symmetric file encryption secret"] = base64.b64encode(
            self.file_secret
        ).decode("utf-8")
        output["Unencrypted file checksum"] = self.unencrypted_checksum
        output["Encrypted file part checksums (MD5)"] = self.encrypted_md5_checksums
        output["Encrypted file part checksums (SHA256)"] = (
            self.encrypted_sha256_checksums
        )

        if not output_path.parent.exists():
            output_path.mkdir(parents=True)

        # owner read-only
        with output_path.open("w") as file:
            json.dump(output, file, indent=2)
        os.chmod(path=output_path, mode=0o400)

    def to_upload_metadata(self, file_id: str):
        """Convert internal output file representation to unencrypted request model"""
        return LegacyFileUploadMetadata(
            file_id=file_id,
            object_id=self.file_uuid,
            part_size=self.part_size,
            unencrypted_size=self.unencrypted_size,
            encrypted_size=self.encrypted_size,
            file_secret=base64.b64encode(self.file_secret).decode("utf-8"),
            unencrypted_checksum=self.unencrypted_checksum,
            encrypted_md5_checksums=self.encrypted_md5_checksums,
            encrypted_sha256_checksums=self.encrypted_sha256_checksums,
        )

    @classmethod
    def load(cls, input_path: Path):
        """Load metadata from serialized file"""
        with input_path.open("r") as infile:
            data = json.load(infile)

        part_size = int(data["Part Size"].rpartition(" MiB")[0]) * 1024**2

        return LegacyOutputMetadata(
            alias=data["Alias"],
            file_uuid=data["File UUID"],
            original_path=Path(data["Original filesystem path"]),
            part_size=part_size,
            file_secret=base64.b64decode(data["Symmetric file encryption secret"]),
            unencrypted_checksum=data["Unencrypted file checksum"],
            encrypted_md5_checksums=data["Encrypted file part checksums (MD5)"],
            encrypted_sha256_checksums=data["Encrypted file part checksums (SHA256)"],
            unencrypted_size=int(data["Unencrypted file size"]),
            encrypted_size=int(data["Encrypted file size"]),
        )


@dataclass
class OutputMetadata(OutputMetadataBase):
    """Container class for output metadata"""

    secret_id: str

    def serialize(self, output_path: Path):
        """Serialize metadata to file"""
        output: dict[str, Any] = {}
        output["Alias"] = self.alias
        output["File UUID"] = self.file_uuid
        output["Original filesystem path"] = str(self.original_path.resolve())
        output["Part Size"] = f"{self.part_size // 1024**2} MiB"
        output["Unencrypted file size"] = self.unencrypted_size
        output["Encrypted file size"] = self.encrypted_size
        output["Symmetric file encryption secret ID"] = self.secret_id
        output["Unencrypted file checksum"] = self.unencrypted_checksum
        output["Encrypted file part checksums (MD5)"] = self.encrypted_md5_checksums
        output["Encrypted file part checksums (SHA256)"] = (
            self.encrypted_sha256_checksums
        )

        if not output_path.parent.exists():
            output_path.mkdir(parents=True)

        # owner read-only
        with output_path.open("w") as file:
            json.dump(output, file, indent=2)
        os.chmod(path=output_path, mode=0o400)

    def to_upload_metadata(self, file_id: str):
        """Convert internal output file representation to unencrypted request model"""
        return FileUploadMetadata(
            file_id=file_id,
            object_id=self.file_uuid,
            part_size=self.part_size,
            unencrypted_size=self.unencrypted_size,
            encrypted_size=self.encrypted_size,
            secret_id=self.secret_id,
            unencrypted_checksum=self.unencrypted_checksum,
            encrypted_md5_checksums=self.encrypted_md5_checksums,
            encrypted_sha256_checksums=self.encrypted_sha256_checksums,
        )

    @classmethod
    def load(cls, input_path: Path):
        """Load metadata from serialized file"""
        with input_path.open("r") as infile:
            data = json.load(infile)

        part_size = int(data["Part Size"].rpartition(" MiB")[0]) * 1024**2

        return OutputMetadata(
            alias=data["Alias"],
            file_uuid=data["File UUID"],
            original_path=Path(data["Original filesystem path"]),
            part_size=part_size,
            secret_id=data["Symmetric file encryption secret ID"],
            unencrypted_checksum=data["Unencrypted file checksum"],
            encrypted_md5_checksums=data["Encrypted file part checksums (MD5)"],
            encrypted_sha256_checksums=data["Encrypted file part checksums (SHA256)"],
            unencrypted_size=int(data["Unencrypted file size"]),
            encrypted_size=int(data["Encrypted file size"]),
        )
