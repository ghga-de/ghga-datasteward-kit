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

"""Utility functions"""


from pathlib import Path
from typing import TypeVar

import yaml
from ghga_service_commons.utils.simple_token import generate_token_and_hash
from pydantic import BaseSettings

TOKEN_PATH = Path.home() / ".ghga_data_steward_token.txt"
TOKEN_HASH_PATH = Path.home() / ".ghga_data_steward_token_hash.txt"

# pylint: disable=invalid-name
ConfigType = TypeVar("ConfigType", bound=BaseSettings)


class TokenNotExistError(RuntimeError):
    """Raised when token does not exist"""


def load_config_yaml(path: Path, config_cls: type[ConfigType]) -> ConfigType:
    """Load config parameters from the specified YAML file."""

    with open(path, "r", encoding="utf-8") as config_file:
        config_dict = yaml.safe_load(config_file)
    return config_cls(**config_dict)


def save_token_and_hash():
    """Generate tokean and hash and save them into files"""

    token, hash_ = generate_token_and_hash()

    TOKEN_PATH.write_text(data=token)
    TOKEN_HASH_PATH.write_text(data=hash_)

    return token, hash_


def read_token():
    """Read token from file"""
    assert_token_exist()
    return TOKEN_PATH.read_text()


def assert_token_exist():
    """Make sure that token exist, otherwise raise TokenNotExistError"""
    if not TOKEN_PATH.is_file():
        raise TokenNotExistError()
