# Copyright 2023 Universität Tübingen, DKFZ and EMBL
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
"""Envelope creator for testing purposes"""

import base64
from argparse import ArgumentParser, Namespace
from pathlib import Path

import crypt4gh.header
import crypt4gh.keys


def write_envelope(args: Namespace):
    """Generate and write envelope"""
    file_secret = base64.b64decode(args.secret)
    pubkey = crypt4gh.keys.get_public_key(args.public)
    private_key = crypt4gh.keys.get_private_key(args.private, None)

    output_location = Path(args.output)
    if output_location.exists():
        raise FileExistsError(f"File at {output_location} already exists. Aborting.")

    envelope = create_envelope(
        file_secret=file_secret, client_pubkey=pubkey, server_private_key=private_key
    )

    with output_location.open("wb") as file:
        file.write(envelope)


def create_envelope(
    *, file_secret: bytes, client_pubkey: bytes, server_private_key: bytes
) -> bytes:
    """
    Gather file encryption/decryption secret and assemble a crypt4gh envelope using the
    servers private and the clients public key
    """
    keys = [(0, server_private_key, client_pubkey)]
    header_content = crypt4gh.header.make_packet_data_enc(0, file_secret)
    header_packets = crypt4gh.header.encrypt(header_content, keys)
    header_bytes = crypt4gh.header.serialize(header_packets)

    return header_bytes


def main():
    """
    Generate envelope and write to output file.
    """
    parser = ArgumentParser(
        description="Generate envelope and write to output file."
        + " Needs to be prepended to actual file to be decrypted."
        + " Use Crypt4GH command line tool after assembly."
    )
    parser.add_argument(
        "-o", "--output", help="Path to write envelope to", required=True
    )
    parser.add_argument("-p", "--private", help="Path to private key", required=True)
    parser.add_argument("-u", "--public", help="Path to public key", required=True)
    parser.add_argument(
        "-s", "--secret", help="Base 64 encoded file secret", required=True
    )
    args = parser.parse_args()
    write_envelope(args)


if __name__ == "__main__":
    main()
