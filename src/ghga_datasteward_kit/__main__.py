# Copyright 2021 - 2026 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Entrypoint of the package."""

import sys
from importlib.metadata import distribution

from ghga_datasteward_kit.main import run as _run

_NOTICE = """
===============================================================================
NOTICE: This is the final release of ghga-datasteward-kit on PyPI.

Development continues in the GHGA monorepo, where the kit is tested against the
exact service and library versions it is deployed with:

  https://github.com/ghga-de/ghga  (tools/ghga-datasteward-kit)

Future versions are run from a checkout of the monorepo at a release tag rather
than installed from PyPI. See the repository for instructions.
===============================================================================
"""


def _installed_from_pypi() -> bool:
    """Whether this is a wheel from an index (no PEP 610 direct_url.json)."""
    try:
        return distribution(__package__).read_text("direct_url.json") is None
    except Exception:
        return False


def run():
    """Run the CLI, preceded by the PyPI deprecation notice."""
    if _installed_from_pypi():
        print(_NOTICE, file=sys.stderr)
    _run()


if __name__ == "__main__":
    run()
