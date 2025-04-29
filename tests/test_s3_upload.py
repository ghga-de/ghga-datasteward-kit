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

import asyncio
import sys
import threading
import time
from collections.abc import Generator
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import Mock

import httpx
import pytest
import requests
import uvicorn
from fastapi import FastAPI
from ghga_service_commons.api.api import ApiConfigBase
from ghga_service_commons.api.testing import get_free_port
from ghga_service_commons.utils.temp_files import big_temp_file
from hexkit.providers.s3.testutils import S3ContainerFixture
from pytest_httpx import HTTPXMock

from ghga_datasteward_kit.batch_s3_upload import FileMetadata
from ghga_datasteward_kit.batch_s3_upload import main as batch_upload_main
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
    steward_token_fixture,
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


async def test_batch_upload_retries(
    config_fixture: Config,  # noqa: F811
    monkeypatch,
    httpx_mock: HTTPXMock,
):
    """Test the batch upload auto-retry mechanism"""
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

        alias = "test_batch_retry"
        input_path = Path(file.name)

        object_ids = await storage.list_all_object_ids(bucket_id=BUCKET_ID)
        assert len(object_ids) == 0

        with TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            file_overview_tsv = Path(tmp_dir) / "file_overview.tsv"
            legacy_config = LegacyConfig(
                client_exponential_backoff_max=config.client_exponential_backoff_max,
                client_max_parallel_transfers=config.client_max_parallel_transfers,
                client_num_retries=config.client_num_retries,
                object_storages=config.object_storages,
                output_dir=Path(tmp_dir),
                selected_storage_alias="test",
            )

            files = [FileMetadata(path=input_path, alias=alias)]

            monkeypatch.setattr(
                "ghga_datasteward_kit.batch_s3_upload.load_config_yaml",
                lambda path, config_cls: legacy_config,
            )
            monkeypatch.setattr(
                "ghga_datasteward_kit.batch_s3_upload.load_file_metadata",
                lambda file_overview_tsv: files,
            )

            # Use a mock for trigger_file_upload to see how many times it gets called
            trigger_mock = Mock()
            trigger_mock.side_effect = RuntimeError()
            monkeypatch.setattr(
                "ghga_datasteward_kit.batch_s3_upload.BatchUploadManager._start_next_file",
                trigger_mock,
            )

            with pytest.raises(RuntimeError):
                batch_upload_main(
                    config_path=config_path,
                    file_overview_tsv=file_overview_tsv,
                    parallel_processes=1,
                    legacy_mode=True,
                    dry_run=True,
                    max_retries=3,
                )
        assert trigger_mock.call_count == 4


async def test_batch_upload(config_fixture: Config, steward_token_fixture, monkeypatch):  # noqa: F811
    """Test whole batch upload process for s3_upload script.

    The test will create one test file and upload it twice under different aliases
    We have to do some special stuff because monkey patching doesn't work when
    the batch uploader executes the shell commands to do the individual file uploads.

    The special stuff involves writing some actual test files:
    - YAML config file
    - TSV file overview
    - TXT token file (handled automatically by the `steward_token_fixture`)
        - in the unlikely event this test is run on a computer where a real token file
        already exists at TOKEN_PATH, the fixture will temporarily rename it for the
        duration of the test.

    The special stuff also involves running a web server in another thread. We can't
    use httpx_mock because that relies on monkey patching. The test endpoints are:
    - /health (only used for `wait_until_responsive`)
    - /wkvs/values/storage_aliases (for providing the dummy storage map)
    - /federated/ingest_secret (for providing the dummy secret ID)
    """
    # Create a test FastAPI app that stands in for external calls.
    app = FastAPI()

    @app.get("/health")
    def health():
        return 200

    @app.get("/wkvs/values/storage_aliases")
    def get_storage_map():
        return {"storage_aliases": {"test": s3_config.s3_endpoint_url}}

    @app.post("/federated/ingest_secret")
    async def exchange_secret():
        return {"secret_id": "test-secret-id"}

    def start_server(server_instance):
        """Starts the test server (called in another thread)."""
        asyncio.run(server_instance.serve())

    def wait_until_responsive(url, timeout=5.0):
        """Checks for test server's readiness instead of guessing with `sleep`"""
        start = time.time()
        while True:
            try:
                r = requests.get(url)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            if time.time() - start > timeout:
                raise TimeoutError("Server didn't respond in time.")
            time.sleep(0.1)

    # Get a free port for the test server
    free_port = get_free_port()
    wkvs_url = f"http://127.0.0.1:{free_port}/wkvs"

    # Set up the S3 container fixture and the temporary file that we'll to upload to S3
    with (
        S3ContainerFixture() as container,
        big_temp_file(FILE_SIZE) as file,
    ):
        # Establish the object storages config with the S3 fixture's info
        s3_config = container.s3_config
        config = config_fixture.model_copy(
            update={
                "wkvs_api_url": wkvs_url,
                "object_storages": storage_config(
                    s3_access_key_id=s3_config.s3_access_key_id,
                    s3_secret_access_key=s3_config.s3_secret_access_key.get_secret_value(),
                    bucket_id=BUCKET_ID,
                ),
            }
        )

        # Write a real file overview TSV to the temp dir created by the config fixture
        file_overview_tsv = config.output_dir / "file_overview.tsv"
        with open(file_overview_tsv, "w") as file_overview:
            file_overview.write(f"{Path(file.name)}\t{ALIAS}")
            file_overview.write(f"\n{Path(file.name)}\t{ALIAS}2")

        # The subprocess will load config from the supplied path, so we have to
        #  actually write out a file. Can't do a simple yaml dump because it doesn't
        #  work with the secret strings (they get masked) and we need to supply
        #  some custom URLs anyway
        cfg = f"""
object_storages:
  test:
    bucket_id: "test-bucket"
    credentials:
      s3_access_key_id: "{s3_config.s3_access_key_id}"
      s3_secret_access_key: "{s3_config.s3_secret_access_key.get_secret_value()}"
part_size: 16
output_dir: {config.output_dir}
selected_storage_alias: "{config.selected_storage_alias}"
wkvs_api_url: "{wkvs_url}"
client_exponential_backoff_max: 10
client_retry_status_codes: [408, 500, 502, 503, 504]
client_timeout: 5
client_max_parallel_transfers: 10
client_num_retries: 5
secret_ingest_pubkey: "{config.secret_ingest_pubkey}"
secret_ingest_baseurl: "http://127.0.0.1:{free_port}"
"""

        # Put all that info into a config yaml file to be loaded later
        with open(config.output_dir / "cfg.yaml", "w") as f:
            f.write(cfg)
        config_path = config.output_dir / "cfg.yaml"

        # Create uvicorn server config
        api_config = ApiConfigBase(port=free_port)
        uv_config = uvicorn.Config(
            app=app,
            host=api_config.host,
            port=api_config.port,
            log_config=None,
            reload=api_config.auto_reload,
            workers=api_config.workers,
        )

        # Need a reference to the server so we can tell it to shut down later
        server = uvicorn.Server(uv_config)

        server_thread = threading.Thread(
            target=start_server, args=(server,), daemon=True
        )
        server_thread.start()
        test_url = f"http://127.0.0.1:{api_config.port}/health"
        try:
            wait_until_responsive(test_url)

            # Misc S3 setup
            storage = get_object_storage(config=config)
            await storage.create_bucket(bucket_id=get_bucket_id(config))
            sys.set_int_max_str_digits(FILE_SIZE)

            batch_upload_main(
                config_path=config_path,
                file_overview_tsv=file_overview_tsv,
                parallel_processes=1,
                legacy_mode=False,
                dry_run=False,
                max_retries=0,
            )

            # Verify that the output files exists
            json_filepath = (config.output_dir / ALIAS).with_suffix(".json")
            json_filepath2 = (config.output_dir / f"{ALIAS}2").with_suffix(".json")
            assert json_filepath.exists(), "Did not find first output JSON file"
            assert json_filepath2.exists(), "Did not find second output JSON file"

            # Run batch upload again just to make sure no errors arise
            batch_upload_main(
                config_path=config_path,
                file_overview_tsv=file_overview_tsv,
                parallel_processes=1,
                legacy_mode=False,
                dry_run=False,
                max_retries=5,
            )
        finally:
            # Tell the server to shut down
            server.should_exit = True
            server_thread.join(timeout=10)
