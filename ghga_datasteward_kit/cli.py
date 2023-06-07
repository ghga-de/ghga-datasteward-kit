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

from ghga_datasteward_kit import batch_s3_upload, catalog_accession_generator, s3_upload

cli = typer.Typer()


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
def upload_single_file(
    input_path: Path = typer.Option(..., help="Local path of the input file"),
    alias: str = typer.Option(..., help="A human readable file alias"),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
):
    """Upload a single file to S3."""

    s3_upload.main(input_path=input_path, alias=alias, config_path=config_path)


@cli.command()
def upload_multiple_files(
    tsv: Path = typer.Option(
        ...,
        help=(
            "Path to a tsv file with the first column containing the file path and the"
            + " second column containing the file alias."
        ),
    ),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
    parallel_processes: int = typer.Option(..., help="Number of parallel uploads."),
    dry_run: bool = typer.Option(
        False,
        help=("Only print commands for each file." + " No uploads are performed."),
    ),
):
    """Upload multiple files to S3."""

    batch_s3_upload.main(
        file_overview_tsv=tsv,
        config_path=config_path,
        parallel_processes=parallel_processes,
        dry_run=dry_run,
    )
