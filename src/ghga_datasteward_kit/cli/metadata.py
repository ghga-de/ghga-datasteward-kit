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

"""Metadata related CLI"""

import logging
from pathlib import Path

import typer
from ghga_transpiler.cli import transpile

from ghga_datasteward_kit import metadata

cli = typer.Typer()

cli.command()(transpile)


@cli.command()
def submit(
    submission_title: str = typer.Option(..., help="The title of the submission."),
    submission_description: str = typer.Option(
        ..., help="The description of the submission."
    ),
    metadata_path: Path = typer.Option(
        ...,
        help="The path to the metadata JSON file.",
        exists=True,
        dir_okay=False,
        file_okay=True,
        readable=True,
    ),
    config_path: Path = typer.Option(
        ...,
        help="Path to a config YAML.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
    ),
):
    """Submit metadata to local submission registry (no upload takes place)."""
    logging.basicConfig(level=logging.CRITICAL)
    metadata.submit_metadata_from_path(
        submission_title=submission_title,
        submission_description=submission_description,
        metadata_path=metadata_path,
        config_path=config_path,
    )


@cli.command()
def generate_artifact_models(
    config_path: Path = typer.Option(
        ...,
        help="Path to a config YAML.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    """Run transformation workflow to generate artifact models."""
    logging.basicConfig(level=logging.CRITICAL)
    metadata.generate_artifact_models_from_path(config_path=config_path)


@cli.command()
def transform(
    config_path: Path = typer.Option(
        ...,
        help="Path to a config YAML.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    """Run transformation workflow on submitted metadata to produce artifacts."""
    logging.basicConfig(level=logging.CRITICAL)
    metadata.transform_metadata_from_path(config_path=config_path)
