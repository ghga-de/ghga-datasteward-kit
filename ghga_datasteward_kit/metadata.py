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

"""Submit metadata to the submission registry."""

import asyncio
from pathlib import Path

import yaml
from metldata.accession_registry.accession_registry import AccessionRegistry
from metldata.accession_registry.accession_store import AccessionStore
from metldata.accession_registry.config import Config as AccessionConfig
from metldata.builtin_workflows.ghga_archive import GHGA_ARCHIVE_WORKFLOW
from metldata.custom_types import Json
from metldata.event_handling.event_handling import FileSystemEventPublisher
from metldata.submission_registry.config import Config as SubmissionConfig
from metldata.submission_registry.event_publisher import SourceEventPublisher
from metldata.submission_registry.models import SubmissionHeader
from metldata.submission_registry.submission_registry import SubmissionRegistry
from metldata.submission_registry.submission_store import SubmissionStore
from metldata.transform.main import (
    TransformationEventHandlingConfig,
    run_workflow_on_all_source_events,
)
from pydantic import Field

from ghga_datasteward_kit.utils import load_config_yaml


class MetadataConfig(  # pylint: disable=too-many-ancestors
    SubmissionConfig,
    AccessionConfig,
    TransformationEventHandlingConfig,
):
    """Config parameters used for submission and transformation of metadata."""

    workflow_config: GHGA_ARCHIVE_WORKFLOW.config_cls = Field(
        ..., description="Configuration for the metadata transfornation workflow."
    )


def submit_metadata(
    *,
    submission_title: str,
    submission_description: str,
    metadata: Json,
    config: MetadataConfig
) -> str:
    """Submit metadata to the submission registry."""

    submission_store = SubmissionStore(config=config)
    event_publisher = FileSystemEventPublisher(config=config)
    source_event_publisher = SourceEventPublisher(
        config=config, provider=event_publisher
    )
    accession_store = AccessionStore(config=config)
    accession_registry = AccessionRegistry(
        config=config, accession_store=accession_store
    )
    submission_registry = SubmissionRegistry(
        config=config,
        submission_store=submission_store,
        event_publisher=source_event_publisher,
        accession_registry=accession_registry,
    )

    submission_header = SubmissionHeader(
        title=submission_title, description=submission_description
    )
    submission_id = submission_registry.init_submission(header=submission_header)
    submission_registry.upsert_submission_content(
        submission_id=submission_id, content=metadata
    )
    submission_registry.complete_submission(id_=submission_id)

    return submission_id


def submit_metadata_from_path(
    *,
    submission_title: str,
    submission_description: str,
    metadata_path: Path,
    config_path: Path
):
    """Read metadata and config from the specified paths and then submit
    metadata to the submission registry."""

    with open(metadata_path, "r", encoding="utf8") as metadata_file:
        metadata = yaml.safe_load(metadata_file)

    config = load_config_yaml(path=config_path, config_cls=MetadataConfig)

    return submit_metadata(
        submission_title=submission_title,
        submission_description=submission_description,
        metadata=metadata,
        config=config,
    )


def transform_metadata(*, config: MetadataConfig) -> None:
    """Run transformation workflow on submitted metadata to produce artifacts."""

    asyncio.run(
        run_workflow_on_all_source_events(
            event_config=config,
            workflow_definition=GHGA_ARCHIVE_WORKFLOW,
            worflow_config=config.workflow_config,
            original_model=config.metadata_model,
        )
    )


def transform_metadata_from_path(*, config_path: Path) -> None:
    """Load config from path and run transformation workflow on submitted
    metadata to produce artifacts."""

    config = load_config_yaml(path=config_path, config_cls=MetadataConfig)

    transform_metadata(config=config)
