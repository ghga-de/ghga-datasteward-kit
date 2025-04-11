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

"""Testing the whole encryption, upload, validation flow"""

import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

import httpx
import pytest
from ghga_service_commons.utils.temp_files import big_temp_file
from hexkit.providers.s3.testutils import S3ContainerFixture
from pytest_httpx import HTTPXMock

from ghga_datasteward_kit.s3_upload import Config, LegacyConfig, exceptions
from ghga_datasteward_kit.s3_upload.entrypoint import (
    async_main,
    check_adjust_input_file,
    legacy_async_main,
)
from ghga_datasteward_kit.s3_upload.multipart_upload import MultipartUpload
from ghga_datasteward_kit.s3_upload.utils import (
    get_bucket_id,
    get_object_storage,
)
from ghga_datasteward_kit.utils import path_join
from tests.fixtures.config import (  # noqa: F401
    config_fixture,
    legacy_config_fixture,
    storage_config,
)

ALIAS = "test_file"
BUCKET_ID = "test-bucket"
FILE_SIZE = 50 * 1024**2

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.httpx_mock(
        assert_all_responses_were_requested=False,
        can_send_already_matched_responses=True,
        should_mock=lambda request: request.url.host
        not in ("127.0.0.1", "localhost", "host.docker.internal"),
    ),
]


async def test_legacy_process(
    legacy_config_fixture: LegacyConfig,  # noqa: F811
    httpx_mock: HTTPXMock,
    monkeypatch,
):
    """Test whole upload/download process for s3_upload script"""
    with S3ContainerFixture() as container:
        s3_config = container.s3_config

        config = legacy_config_fixture.model_copy(
            update={
                "object_storages": storage_config(
                    s3_access_key_id=s3_config.s3_access_key_id,
                    s3_secret_access_key=s3_config.s3_secret_access_key.get_secret_value(),
                    bucket_id=BUCKET_ID,
                ),
            }
        )
        httpx_mock.add_response(
            url=path_join(config.wkvs_api_url, "values/storage_aliases"),
            json={"storage_aliases": {"test": s3_config.s3_endpoint_url}},
            status_code=200,
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=get_bucket_id(config))
        sys.set_int_max_str_digits(FILE_SIZE)

        with (
            monkeypatch.context() as patch,
            pytest.raises(exceptions.WritingOutputError),
        ):

            def raise_checksum_processing_exception(output_path: Path):
                """Mock to be used as patch for raising a custom exception"""
                raise KeyboardInterrupt()

            patch.setattr(
                "ghga_datasteward_kit.models.LegacyOutputMetadata.serialize",
                raise_checksum_processing_exception,
            )
            with big_temp_file(FILE_SIZE) as file:
                await legacy_async_main(
                    input_path=Path(file.name), alias=ALIAS, config=config
                )
        # ensure output file does not exist
        assert not (config.output_dir / ALIAS).with_suffix(".json").exists()

        with big_temp_file(FILE_SIZE) as file:
            await legacy_async_main(
                input_path=Path(file.name), alias=ALIAS, config=config
            )
        # output file exists?
        assert (config.output_dir / ALIAS).with_suffix(".json").exists()


async def test_process(config_fixture: Config, monkeypatch, httpx_mock: HTTPXMock):  # noqa: F811
    """Test whole upload/download process for s3_upload script"""

    async def secret_exchange_dummy(
        *,
        file_id: str,
        secret: bytes,
        token: str,
        config: Config,
    ):
        return "test-secret-id"

    with S3ContainerFixture() as container:
        s3_config = container.s3_config

        config = config_fixture.model_copy(
            update={
                "object_storages": storage_config(
                    s3_access_key_id=s3_config.s3_access_key_id,
                    s3_secret_access_key=s3_config.s3_secret_access_key.get_secret_value(),
                    bucket_id=BUCKET_ID,
                ),
            }
        )
        httpx_mock.add_response(
            url=path_join(config.wkvs_api_url, "values/storage_aliases"),
            json={"storage_aliases": {"test": s3_config.s3_endpoint_url}},
            status_code=200,
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=get_bucket_id(config))
        sys.set_int_max_str_digits(FILE_SIZE)

        with big_temp_file(FILE_SIZE) as file:
            with (
                monkeypatch.context() as patch,
                pytest.raises(exceptions.WritingOutputError),
            ):

                def raise_checksum_processing_exception(output_path: Path):
                    """Mock to be used as patch for raising a custom exception"""
                    raise KeyboardInterrupt()

                patch.setattr(
                    "ghga_datasteward_kit.models.OutputMetadata.serialize",
                    raise_checksum_processing_exception,
                )
                patch.setattr(
                    "ghga_datasteward_kit.s3_upload.entrypoint.exchange_secret_for_id",
                    secret_exchange_dummy,
                )
                await async_main(
                    input_path=Path(file.name),
                    alias=ALIAS,
                    config=config,
                    token="dummy-token",
                )

            with monkeypatch.context() as patch:
                patch.setattr(
                    "ghga_datasteward_kit.s3_upload.entrypoint.exchange_secret_for_id",
                    secret_exchange_dummy,
                )
                await async_main(
                    input_path=Path(file.name),
                    alias=ALIAS,
                    config=config,
                    token="dummy-token",
                )
            # output file exists?
            assert (config.output_dir / ALIAS).with_suffix(".json").exists()


async def test_error_handling_local_checksum_validation(
    config_fixture: Config,  # noqa: F811
    monkeypatch,
    httpx_mock: HTTPXMock,
):
    """Test upload context manager error handling and cleanup when raising local checksum validation errors."""
    sys.set_int_max_str_digits(FILE_SIZE)
    with S3ContainerFixture() as container, big_temp_file(FILE_SIZE) as file:
        s3_config = container.s3_config
        config = config_fixture.model_copy(
            update={
                "object_storages": storage_config(
                    s3_access_key_id=s3_config.s3_access_key_id,
                    s3_secret_access_key=s3_config.s3_secret_access_key.get_secret_value(),
                    bucket_id=BUCKET_ID,
                ),
            }
        )
        httpx_mock.add_response(
            url=path_join(config.wkvs_api_url, "values/storage_aliases"),
            json={"storage_aliases": {"test": s3_config.s3_endpoint_url}},
            status_code=200,
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=get_bucket_id(config))

        alias = "test_error_handling"
        input_path = Path(file.name)
        file_size = await check_adjust_input_file(
            input_path=input_path, alias=alias, config=config
        )

        object_ids = await storage.list_all_object_ids(bucket_id=BUCKET_ID)
        assert len(object_ids) == 0

        object_id = ""
        # check encryption/decryption errors raise correctly
        with pytest.raises(exceptions.ShouldDeleteObjectError):
            async with MultipartUpload(file_size=file_size, config=config) as upload:
                object_id = upload.file_id
                with monkeypatch.context() as patch:

                    def raise_checksum_processing_exception(
                        self,
                        *,
                        bucket_id: str,
                        object_id: str,
                        encryption_file_sha256: str,
                    ):
                        """Mock to be used as patch for raising a custom exception"""
                        raise exceptions.ChecksumValidationError(
                            bucket_id=BUCKET_ID,
                            object_id=object_id,
                            message="Expected test failure.",
                        )

                    patch.setattr(
                        "ghga_datasteward_kit.s3_upload.uploader.Decryptor.complete_processing",
                        raise_checksum_processing_exception,
                    )
                    await upload.validate_and_transfer_content(input_path=input_path)

        assert not await storage.does_object_exist(
            bucket_id=BUCKET_ID, object_id=object_id
        )
        assert not await storage._list_multipart_upload_for_object(
            bucket_id=BUCKET_ID, object_id=object_id
        )


async def test_error_handling_remote_checksum_validation(
    config_fixture: Config,  # noqa: F811
    monkeypatch,
    httpx_mock: HTTPXMock,
):
    """Test upload context manager error handling and cleanup when raising remote checksum validation errors."""
    sys.set_int_max_str_digits(FILE_SIZE)
    with S3ContainerFixture() as container, big_temp_file(FILE_SIZE) as file:
        s3_config = container.s3_config
        config = config_fixture.model_copy(
            update={
                "object_storages": storage_config(
                    s3_access_key_id=s3_config.s3_access_key_id,
                    s3_secret_access_key=s3_config.s3_secret_access_key.get_secret_value(),
                    bucket_id=BUCKET_ID,
                ),
            }
        )
        httpx_mock.add_response(
            url=path_join(config.wkvs_api_url, "values/storage_aliases"),
            json={"storage_aliases": {"test": s3_config.s3_endpoint_url}},
            status_code=200,
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=get_bucket_id(config))

        alias = "test_error_handling"
        input_path = Path(file.name)
        file_size = await check_adjust_input_file(
            input_path=input_path, alias=alias, config=config
        )

        object_ids = await storage.list_all_object_ids(bucket_id=BUCKET_ID)
        assert len(object_ids) == 0

        object_id = ""
        # check content MD5 comparison errors raise correctly
        with pytest.raises(exceptions.ShouldDeleteObjectError):
            async with MultipartUpload(file_size=file_size, config=config) as upload:
                object_id = upload.file_id
                with monkeypatch.context() as patch:

                    def raise_content_checksum_exception(self):
                        """Mock to be used as patch for raising a custom exception"""
                        raise exceptions.ChecksumValidationError(
                            bucket_id=BUCKET_ID,
                            object_id=object_id,
                            message="Expected test failure.",
                        )

                    patch.setattr(
                        "ghga_datasteward_kit.s3_upload.multipart_upload.MultipartUpload.check_md5_matches",
                        raise_content_checksum_exception,
                    )
                    await upload.validate_and_transfer_content(input_path=input_path)

        assert not await storage.does_object_exist(
            bucket_id=BUCKET_ID, object_id=object_id
        )
        assert not await storage._list_multipart_upload_for_object(
            bucket_id=BUCKET_ID, object_id=object_id
        )


async def test_error_handling_upload_completion(
    config_fixture: Config,  # noqa: F811
    monkeypatch,
    httpx_mock: HTTPXMock,
):
    """Test upload context manager error handling and cleanup when raising upload completion errors."""
    sys.set_int_max_str_digits(FILE_SIZE)
    with S3ContainerFixture() as container, big_temp_file(FILE_SIZE) as file:
        s3_config = container.s3_config
        config = config_fixture.model_copy(
            update={
                "object_storages": storage_config(
                    s3_access_key_id=s3_config.s3_access_key_id,
                    s3_secret_access_key=s3_config.s3_secret_access_key.get_secret_value(),
                    bucket_id=BUCKET_ID,
                ),
            }
        )
        httpx_mock.add_response(
            url=path_join(config.wkvs_api_url, "values/storage_aliases"),
            json={"storage_aliases": {"test": s3_config.s3_endpoint_url}},
            status_code=200,
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=get_bucket_id(config))

        alias = "test_error_handling"
        input_path = Path(file.name)
        file_size = await check_adjust_input_file(
            input_path=input_path, alias=alias, config=config
        )

        object_ids = await storage.list_all_object_ids(bucket_id=BUCKET_ID)
        assert len(object_ids) == 0

        object_id = ""
        # check upload completion errors are raised correctly
        with pytest.raises(exceptions.ShouldAbortUploadError):
            async with MultipartUpload(file_size=file_size, config=config) as upload:
                object_id = upload.file_id

                async def raise_upload_completion_exception(
                    *,
                    upload_id: str,
                    bucket_id: str,
                    object_id: str,
                    anticipated_part_quantity: int | None = None,
                    anticipated_part_size: int | None = None,
                ):
                    """Mock to be used as patch for raising a custom exception"""
                    raise exceptions.MultipartUploadCompletionError(
                        cause="This should fail for testing purposes.",
                        bucket_id=BUCKET_ID,
                        object_id=ALIAS,
                        upload_id=upload.upload_id,
                    )

                upload.storage.complete_multipart_upload = (
                    raise_upload_completion_exception
                )

                await upload.validate_and_transfer_content(input_path=input_path)

        assert not await storage.does_object_exist(
            bucket_id=BUCKET_ID, object_id=object_id
        )
        assert not await storage._list_multipart_upload_for_object(
            bucket_id=BUCKET_ID, object_id=object_id
        )


async def test_error_handling_part_upload(
    config_fixture: Config,  # noqa: F811
    monkeypatch,
    httpx_mock: HTTPXMock,
):
    """Test upload context manager error handling and cleanup when raising part upload errors."""
    sys.set_int_max_str_digits(FILE_SIZE)
    with S3ContainerFixture() as container, big_temp_file(FILE_SIZE) as file:
        s3_config = container.s3_config
        config = config_fixture.model_copy(
            update={
                "object_storages": storage_config(
                    s3_access_key_id=s3_config.s3_access_key_id,
                    s3_secret_access_key=s3_config.s3_secret_access_key.get_secret_value(),
                    bucket_id=BUCKET_ID,
                ),
            }
        )
        httpx_mock.add_response(
            url=path_join(config.wkvs_api_url, "values/storage_aliases"),
            json={"storage_aliases": {"test": s3_config.s3_endpoint_url}},
            status_code=200,
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=get_bucket_id(config))

        alias = "test_error_handling"
        input_path = Path(file.name)
        file_size = await check_adjust_input_file(
            input_path=input_path, alias=alias, config=config
        )

        object_ids = await storage.list_all_object_ids(bucket_id=BUCKET_ID)
        assert len(object_ids) == 0

        object_id = ""
        # check part upload errors raise correctly
        with pytest.raises(exceptions.ShouldAbortUploadError):
            async with MultipartUpload(file_size=file_size, config=config) as upload:
                object_id = upload.file_id
                with monkeypatch.context() as patch:

                    async def raise_part_upload_exception(
                        self,
                        *,
                        client: httpx.AsyncClient,
                        file_processor: Generator[tuple[int, bytes], Any, None],
                        start: float,
                    ):
                        """Mock to be used as patch for raising a custom exception"""
                        raise exceptions.PartUploadError(
                            cause="Expected test failure",
                            bucket_id=BUCKET_ID,
                            object_id=object_id,
                            upload_id=upload.upload_id,
                            part_number=0,
                        )

                    patch.setattr(
                        "ghga_datasteward_kit.s3_upload.uploader.ChunkedUploader.send_part",
                        raise_part_upload_exception,
                    )
                    await upload.validate_and_transfer_content(input_path=input_path)

        assert not await storage.does_object_exist(
            bucket_id=BUCKET_ID, object_id=object_id
        )
        assert not await storage._list_multipart_upload_for_object(
            bucket_id=BUCKET_ID, object_id=object_id
        )
