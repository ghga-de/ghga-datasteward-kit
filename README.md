# GHGA Data Steward Kit

Utilities for data stewards interacting with GHGA infrastructure.

## Installation:

This package can be installed using pip:

```
pip install ghga-datasteward-kit
```

## Usage:

An overview of all commands is provided using:

```
ghga-datasteward-kit --help
```

The following paragraphs provide additional help for using the different commands:

### s3-upload

This command facilitates encrypting files using Crypt4GH and uploading the encrypted
content to a (remote) S3-compatible object storage.
This process consists of multiple steps:
1. Generate a unique file id
2. Create unencrypted file checksum
3. Encrypt file
4. Extract file secret and remove Crypt4GH envelope
5. Upload encrypted file content
6. Download encrypted file content, decrypt and verify checksum
7. Write file/upload information to output file

The user needs to provide a config yaml containing information as described
[here](./s3_upload_config.md).

In addition to these general configuration options, each invocation of this script needs
2 additional parameters passed to the command line:
1. The path to the file on the local file system
2. A human readable alias for the file (choose a unique one)

An output file is written to the specified output directory under \<alias\>.json.
If such a file already exists, an error is thrown.

The resulting file is owner read-only and contains the following information:
1. The file alias
2. A unique identifier for the file
3. The local file path
4. A SHA256 checksum over the unencrypted content
5. MD5 checksums over all encrypted file parts
6. SHA256 checksums over all encrypted file parts
7. The file encryption/decryption secret

Attention: Keep this output file in a safe, private location.
If this file is lost, the uploaded file content becomes inaccessible.

### generate-catalog-accessions

A command for generating accessions for the metadata catalog. Accessions wiil be
stored in a text file.

## Development
For setting up the development environment, we rely on the
[devcontainer feature](https://code.visualstudio.com/docs/remote/containers) of vscode
in combination with Docker Compose.

To use it, you have to have Docker Compose as well as vscode with its "Remote - Containers" extension (`ms-vscode-remote.remote-containers`) installed.
Then open this repository in vscode and run the command
`Remote-Containers: Reopen in Container` from the vscode "Command Palette".

This will give you a full-fledged, pre-configured development environment including:
- infrastructural dependencies (databases, etc.)
- all relevant vscode extensions pre-installed
- pre-configured linting and auto-formating
- a pre-configured debugger
- automatic license-header insertion

If you prefer not to use vscode, you could get a similar setup (without the editor specific features)
by running the following commands:
``` bash
# Execute in the repo's root dir:
cd ./.devcontainer

# build and run the environment with docker-compose
docker-compose up

# attach to the main container:
# (you can open multiple shell sessions like this)
docker exec -it devcontainer_app_1 /bin/bash
```

## License
This repository is free to use and modify according to the [Apache 2.0 License](./LICENSE).
