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

"""Metadata related CLI"""

import logging
from pathlib import Path

import typer
from ghga_transpiler.cli import transpile

from ghga_datasteward_kit import metadata

cli = typer.Typer(no_args_is_help=True)

cli.command(no_args_is_help=True)(transpile)


@cli.command(no_args_is_help=True)
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


@cli.command(no_args_is_help=True)
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


@cli.command(no_args_is_help=True)
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


@cli.command()
def compare_aliases(
    metadata_path: Path = typer.Argument(
        ...,
        help="The path to the metadata JSON file.",
        exists=True,
        dir_okay=False,
        file_okay=True,
        readable=True,
    ),
    tsv: Path = typer.Argument(
        ...,
        help=(
            "Path to a tsv file with the first column containing the file path and the"
            + " second column containing the file alias."
        ),
        exists=True,
        dir_okay=False,
        file_okay=True,
        readable=True,
    ),
):
    """Compare the file aliases contained in the transpiled metadata JSON file with
    those in the file upload TSV file.

    Any aliases from the file upload TSV file which are absent in the metadata
    JSON file will be reported.
    """
    metadata.compare_aliases(metadata_path=metadata_path, file_overview_tsv=tsv)
