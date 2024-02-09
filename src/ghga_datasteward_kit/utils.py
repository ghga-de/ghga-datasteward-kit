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

from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import yaml
from ghga_service_commons.utils.simple_token import generate_token_and_hash
from pydantic_settings import BaseSettings

DELETION_TOKEN_PATH = Path.home() / ".ghga_file_deletion_token.txt"
DELETION_TOKEN_HASH_PATH = Path.home() / ".ghga_file_deletion_token_hash.txt"
TOKEN_PATH = Path.home() / ".ghga_data_steward_token.txt"
TOKEN_HASH_PATH = Path.home() / ".ghga_data_steward_token_hash.txt"

ConfigType = TypeVar("ConfigType", bound=BaseSettings)


class TokenNotExistError(RuntimeError):
    """Raised when token does not exist"""


@dataclass
class AuthorizationToken:
    """Wrapper class to bundle functionality for different tokens used for file service authorization"""

    token_path: Path
    token_hash_path: Path

    def assert_token_exists(self):
        """Make sure that token exist, otherwise raise TokenNotExistError"""
        if not self.token_path.is_file():
            raise TokenNotExistError()

    def read_token(self):
        """Read token from file"""
        self.assert_token_exists()
        return self.token_path.read_text().strip()

    def save_token_and_hash(self):
        """Generate token and hash and save them into files"""
        token, hash_ = generate_token_and_hash()

        self.token_path.write_text(data=token)
        self.token_hash_path.write_text(data=hash_)

        return token, hash_


def load_config_yaml(path: Path, config_cls: type[ConfigType]) -> ConfigType:
    """Load config parameters from the specified YAML file."""
    with open(path, encoding="utf-8") as config_file:
        config_dict = yaml.safe_load(config_file)
    return config_cls(**config_dict)


DELETION_TOKEN = AuthorizationToken(
    token_path=DELETION_TOKEN_PATH, token_hash_path=DELETION_TOKEN_HASH_PATH
)
STEWARD_TOKEN = AuthorizationToken(
    token_path=TOKEN_PATH, token_hash_path=TOKEN_HASH_PATH
)
