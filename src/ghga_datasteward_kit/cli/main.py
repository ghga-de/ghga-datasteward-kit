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

"""The command line interface of the package."""

from pathlib import Path

import typer

from ghga_datasteward_kit import catalog_accession_generator, loading
from ghga_datasteward_kit.cli.file import cli as file_cli
from ghga_datasteward_kit.cli.metadata import cli as metadata_cli
from ghga_datasteward_kit.utils import (
    TOKEN_HASH_PATH,
    TOKEN_PATH,
    TokenNotExistError,
    assert_token_exist,
    save_token_and_hash,
)

cli = typer.Typer()
cli.add_typer(file_cli, name="files", help="File related operations.")
cli.add_typer(metadata_cli, name="metadata", help="Metadata related operations.")


@cli.command()
def generate_catalog_accessions(
    *,
    store_path: Path = typer.Option(
        ...,
        help=(
            "The path to the accession store which is a text file that has to exist."
        ),
    ),
    resource_type: str = typer.Option(
        ...,
        help=(
            "The resource type for which to generate accessions. Can be one of: "
            f"{list(catalog_accession_generator.RESOURCE_PREFIXES.keys())}"
        ),
    ),
    number: int = typer.Option(..., help="The number of accessions to generate."),
) -> None:
    """Generate Metadata Catalog Accessions for the specified resource type.

    The accessions will be stored in the specified accession store and returned to
    stdout.
    """

    accessions = catalog_accession_generator.main(
        store_path=store_path, resource_type=resource_type.lower(), number=number
    )

    for accession in accessions:
        typer.echo(accession)


@cli.command()
def load(
    *,
    config_path: Path = typer.Option(
        ...,
        help="A path to a config YAML.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    """Make files and metadata publicly available in the running system."""
    loading.load(config_path=config_path)


@cli.command()
def generate_credentials(
    overwrite: bool = typer.Option(
        False, help="If specify, overwrite the existing credentials"
    )
):
    """Generate credentials, save them into file and return hash together with file paths"""
    if not overwrite:
        try:
            assert_token_exist()
        except TokenNotExistError:
            pass
        else:
            typer.echo('The token file already exist, use the "overwrite" to overwrite')
            raise typer.Abort()

    _, hash_ = save_token_and_hash()

    typer.echo("Successfully generated credentials")
    typer.echo(f"The token can be found in file: {TOKEN_PATH}")
    typer.echo(f"The token hash can be found in file: {TOKEN_HASH_PATH}")
    typer.echo(f'The token hash: "{hash_}"')
