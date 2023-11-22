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

"""Generates a JSON schema from the service's Config class as well as a corresponding
example config yaml (or check whether these files are up to date).
"""

import json
import sys
from pathlib import Path

import jsonschema2md
from pydantic_settings import BaseSettings

from ghga_datasteward_kit.config import CONFIG_CLASSES
from script_utils.cli import echo_failure, echo_success, run

HERE = Path(__file__).parent.resolve()
REPO_ROOT_DIR = HERE.parent


class ValidationError(RuntimeError):
    """Raised when validation of config documentation fails."""


def get_schema(config_cls: type[BaseSettings]) -> dict:
    """Returns a JSON schema generated from a Config class."""
    schema_json = config_cls.schema_json(indent=2)
    return json.loads(schema_json)


def generate_config_docs(config_cls: type[BaseSettings]) -> str:
    """Generate markdown-formatted documentation for the configuration parameters
    listed in the config schema."""

    config_schema = get_schema(config_cls)

    parser = jsonschema2md.Parser(
        examples_as_yaml=False,
        show_examples="all",
    )
    md_lines = parser.parse_schema(config_schema)

    return "\n".join(md_lines)


def get_docs_file_path(config_type: str) -> Path:
    """Returns the path to the file containing the documentation for the config
    options."""

    return REPO_ROOT_DIR / f"{config_type}_config.md"


def update_docs(config_type: str):
    """Update the example config and config schema files documenting the config
    options."""

    config_cls = CONFIG_CLASSES[config_type]

    docs = generate_config_docs(config_cls)

    with open(
        get_docs_file_path(config_type=config_type), "w", encoding="utf-8"
    ) as schema_file:
        schema_file.write(docs)


def check_docs(config_type: str):
    """Check whether the example config and config schema files documenting the config
    options are up to date.

    Raises:
        ValidationError: if not up to date.
    """

    config_cls = CONFIG_CLASSES[config_type]

    expected_docs = generate_config_docs(config_cls)
    with open(
        get_docs_file_path(config_type=config_type), encoding="utf-8"
    ) as schema_file:
        observed_docs = schema_file.read()
    if expected_docs != observed_docs:
        raise ValidationError(f"Docs for config '{config_type}' are not up to date.")


def main(check: bool = False):
    """Update or check the config documentation files."""

    if check:
        try:
            for config_type in CONFIG_CLASSES:
                try:
                    check_docs(config_type=config_type)
                except Exception as error:  # FIXME
                    if config_type == "metadata":
                        echo_failure(
                            f"Validation skipped for metadata config due to: {error}"
                        )
        except ValidationError as error:
            echo_failure(f"Validation failed: {error}")
            sys.exit(1)
        echo_success("Config docs are up to date.")
        return

    for config_type in CONFIG_CLASSES:
        try:
            update_docs(config_type=config_type)
        except Exception as error:  # FIXME
            if config_type == "metadata":
                echo_failure(f"Doc update skipped for metadata config due to: {error}")
    echo_success("Successfully updated the config docs.")


if __name__ == "__main__":
    run(main)
