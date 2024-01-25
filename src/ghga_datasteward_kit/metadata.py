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
import json
from copy import deepcopy
from pathlib import Path

import yaml
from metldata.accession_registry.accession_registry import AccessionRegistry
from metldata.accession_registry.accession_store import AccessionStore
from metldata.accession_registry.config import Config as AccessionConfig
from metldata.artifacts_rest.artifact_info import load_artifact_info
from metldata.artifacts_rest.models import ArtifactInfo
from metldata.builtin_workflows.ghga_archive import GHGA_ARCHIVE_WORKFLOW
from metldata.custom_types import Json
from metldata.event_handling.event_handling import FileSystemEventPublisher
from metldata.model_utils.essentials import MetadataModel
from metldata.submission_registry.config import Config as SubmissionConfig
from metldata.submission_registry.event_publisher import SourceEventPublisher
from metldata.submission_registry.models import SubmissionHeader
from metldata.submission_registry.submission_registry import SubmissionRegistry
from metldata.submission_registry.submission_store import SubmissionStore
from metldata.transform.handling import WorkflowHandler
from metldata.transform.main import (
    TransformationEventHandlingConfig,
    run_workflow_on_all_source_events,
)
from pydantic import Field

from ghga_datasteward_kit.utils import load_config_yaml


class MetadataConfig(
    SubmissionConfig,
    AccessionConfig,
    TransformationEventHandlingConfig,
):
    """Config parameters used for submission and transformation of metadata."""

    artifact_model_dir: Path = Field(
        default=...,
        description="Path to save the artifact models and artifact infos to.",
    )

    workflow_config: GHGA_ARCHIVE_WORKFLOW.config_cls = Field(
        default=...,
        description="Configuration for the metadata transformation workflow.",
    )


def submit_metadata(
    *,
    submission_title: str,
    submission_description: str,
    metadata: Json,
    config: MetadataConfig,
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
    config_path: Path,
):
    """Read metadata and config from the specified paths and then submit
    metadata to the submission registry.
    """
    with open(metadata_path, encoding="utf8") as metadata_file:
        metadata = yaml.safe_load(metadata_file)

    config = load_config_yaml(path=config_path, config_cls=MetadataConfig)

    return submit_metadata(
        submission_title=submission_title,
        submission_description=submission_description,
        metadata=metadata,
        config=config,
    )


def save_artifact_models(
    *, artifact_models: dict[str, MetadataModel], artifact_model_dir: Path
):
    """Save an artifact model."""
    for artifact_name, artifact_model in artifact_models.items():
        artifact_model_path = artifact_model_dir / f"{artifact_name}_model.yaml"
        artifact_model.write_yaml(path=artifact_model_path)


def save_artifact_infos(
    *, artifact_infos: list[ArtifactInfo], artifact_model_dir: Path
):
    """Save artifact infos."""
    artifact_infos_path = artifact_model_dir / "artifact_infos.json"
    artifact_infos_json = [
        json.loads(artifact_info.json()) for artifact_info in artifact_infos
    ]
    with open(artifact_infos_path, "w", encoding="utf8") as artifact_infos_file:
        json.dump(artifact_infos_json, artifact_infos_file, indent=2)

    simplified_artifact_infos = deepcopy(artifact_infos)
    for artifact_info in simplified_artifact_infos:
        for resource_class in artifact_info.resource_classes.values():
            resource_class.json_schema = {}
    simplified_artifact_infos_path = (
        artifact_model_dir / "simplified_artifact_infos.json"
    )
    simplified_artifact_infos_json = [
        json.loads(artifact_info.json()) for artifact_info in simplified_artifact_infos
    ]
    with open(
        simplified_artifact_infos_path, "w", encoding="utf8"
    ) as simplified_artifact_infos_file:
        json.dump(
            simplified_artifact_infos_json, simplified_artifact_infos_file, indent=2
        )


def get_artifact_infos(
    *,
    artifact_models: dict[str, MetadataModel],
) -> list[ArtifactInfo]:
    """Get artifact infos from artifact models."""
    return [
        load_artifact_info(
            name=artifact_name,
            description=artifact_name,
            model=artifact_model,
        )
        for artifact_name, artifact_model in artifact_models.items()
    ]


def generate_artifact_models(*, config: MetadataConfig) -> None:
    """Generate artifact models and artifact infos and save them to file."""
    if not config.artifact_model_dir.is_dir():
        raise RuntimeError(
            f"Artifact model path {config.artifact_model_dir} is not a directory."
        )

    workflow_handler = WorkflowHandler(
        workflow_definition=GHGA_ARCHIVE_WORKFLOW,
        workflow_config=config.workflow_config,
        original_model=config.metadata_model,
    )

    artifact_infos = get_artifact_infos(
        artifact_models=workflow_handler.artifact_models
    )

    save_artifact_models(
        artifact_models=workflow_handler.artifact_models,
        artifact_model_dir=config.artifact_model_dir,
    )
    save_artifact_infos(
        artifact_infos=artifact_infos, artifact_model_dir=config.artifact_model_dir
    )


def generate_artifact_models_from_path(*, config_path: Path) -> None:
    """Generate artifact models and artifact infos and save them to file."""
    config = load_config_yaml(path=config_path, config_cls=MetadataConfig)

    generate_artifact_models(config=config)


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
    metadata to produce artifacts.
    """
    config = load_config_yaml(path=config_path, config_cls=MetadataConfig)

    transform_metadata(config=config)
