#!/usr/bin/env python3

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

"""Generate Accessions to be used in the Metadata Catalog."""

from pathlib import Path

from metldata.accession_registry.accession_registry import AccessionRegistry
from metldata.accession_registry.accession_store import AccessionStore
from metldata.accession_registry.config import Config

BASE_PREFIX = "GHGAMC"

RESOURCE_PREFIXES = {
    "file": "F",
    "experiment": "X",
    "study": "S",
    "sample": "N",
    "dataset": "D",
    "analysis": "Z",
    "dac": "C",
    "dap": "P",
    "project": "J",
    "publication": "U",
    "biospecimen": "M",
    "individual": "I",
}

SUFFIX_LENGTH = 14


def generate_accessions(
    *, resource_type: str, number: int, accession_registry: AccessionRegistry
) -> list[str]:
    """Generate Accessions to be used in the Metadata Catalog.

    Args:
        resource_type (str): The resource type for which to generate accessions.
        number (int): The number of accessions to generate.
        accession_registry (AccessionRegistry): The accession registry to use.

    Returns:
        list[str]: The generated accessions.
    """
    accessions = [
        accession_registry.get_accession(resource_type=resource_type)
        for _ in range(number)
    ]
    return accessions


def get_config(*, store_path: Path) -> Config:
    """Get the config."""
    prefix_mapping = {
        f"{resource_type}": f"{BASE_PREFIX}{resource_prefix}"
        for resource_type, resource_prefix in RESOURCE_PREFIXES.items()
    }

    return Config(
        prefix_mapping=prefix_mapping,
        suffix_length=SUFFIX_LENGTH,
        accession_store_path=store_path,
    )


def main(*, store_path: Path, resource_type: str, number: int) -> list[str]:
    """Inject dependencies and run the accession generation."""
    if not store_path.exists():
        raise ValueError(f"The specified store path '{store_path}' does not exist.")

    if store_path.is_dir():
        raise ValueError(
            f"The specified store path '{store_path}' is a directory. Please specify "
            "a file path."
        )

    if resource_type not in RESOURCE_PREFIXES:
        raise ValueError(
            f"Unknown resource type '{resource_type}'. Please choose one of: "
            f"{list(RESOURCE_PREFIXES)}"
        )

    config = get_config(store_path=store_path)
    accession_store = AccessionStore(config=config)
    accession_registry = AccessionRegistry(
        config=config, accession_store=accession_store
    )

    return generate_accessions(
        resource_type=resource_type,
        number=number,
        accession_registry=accession_registry,
    )
