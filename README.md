[![tests](https://github.com/ghga-de/ghga-datasteward-kit/actions/workflows/tests.yaml/badge.svg)](https://github.com/ghga-de/ghga-datasteward-kit/actions/workflows/tests.yaml)
[![Coverage Status](https://coveralls.io/repos/github/ghga-de/ghga-datasteward-kit/badge.svg?branch=main)](https://coveralls.io/github/ghga-de/ghga-datasteward-kit?branch=main)

# GHGA Data Steward Kit

Utilities for data stewards interacting with GHGA infrastructure.

## Installation:

This package can be installed using pip:

```
pip install ghga-datasteward-kit
```

## Step by Step Guide

It is important to outline that some commands can only be used by Central Data
Stewards while other commands address Local Data Stewards.

The workflow for both the Local and Central Data Stewards is outlined in the following
paragraphs:

### Local Data Steward

In v1.1 of the Archive, Local Data Stewards are responsible for (A) preparing the metadata
of a submission and (B) for encrypting and uploading the corresponding files to the
Data Hub's S3-compatible Object Storage.

#### A. Metadata Preparation
The data steward kit has no functionality to help with metadata preparation, however,
it is still described here for completeness of the workflow.

To define metadata for a submission, you have two options:

**Option 1:** Use an excel spreadsheet (please do not use Google Spreadsheets because
of data protection). Templates can be found
[here](https://github.com/ghga-de/ghga-metadata-schema/tree/main/spreadsheets). You may
validate the metadata by:
1. Running the [GHGA Metadata Transpiler](https://github.com/ghga-de/ghga-transpiler)
   to generate JSON (as in Option 2).
2. Run the [GHGA Metadata Validator](https://github.com/ghga-de/ghga-validator/)
   on the produced JSON.

**Option 2:** Directly specify the metadata using JSON compliant with our
[LinkML schema](https://github.com/ghga-de/ghga-metadata-schema/blob/main/src/schema/submission.yaml).
Validation of the metadata can be achieved using the
[GHGA Metadata Validator](https://github.com/ghga-de/ghga-validator/).

Once your spreadsheet or JSON file have passed validation, you may send the metadata to
the Central Data Steward.

#### B. File Encryption and Upload:

This is achieved using the data steward kit, using the following steps:

1. **Generate credentials**: The kit interacts with services at GHGA central. To
   authenticate yourself against these services you need to create a set of credentials
   using the `ghga-datasteward-kit generate-credentials` command. Please see
   [this section](#generate-credentials) for further details.

2. **Encrypt and Upload**: File encryption and upload to the S3-compatible object
   storage is done in one go. This is achieved using either the
   `ghga-datasteward-kit files upload` for uploading a single file or the
   `ghga-datasteward-kit files batch-upload` for uploading multiple files at once.
   Please see [this section](#files-batch-upload) for further details. This will output
   one summary JSON per uploaded file. The encryption secret is automatically
   transferred to GHGA central.

Once the upload of all files of a submission has completed, please notify the GHGA
Central Data Steward and provide the summary JSONs obtained in step 2.

### Central Data Steward

The Central Data Steward is responsible for ingesting the metadata and the upload summary files into the running
system. This is performed with the following steps:

1. **Generate credentials**: As for the local data stewards, central data stewards need
   to have credentials for authentication with GHGA Central Services. To create these
   credentials the `ghga-datasteward-kit generate-credentials` command is used.
   Please see [this section](#generate-credentials) for further details.
2. **Transpile Metadata Spreadsheet**: If the Local Data Steward provided a metadata
   spreadsheet, this spreadsheet has to be first transpiled to the JSON format using the
   `ghga-datasteward-kit metadata transpile` command. Please see
   [this section](#metadata) for further details.
3. **Include in Submission Registry**: The submission JSON is included in a
   submission registry on the local file system using the
   `ghga-datasteward-kit metadata submit` command. Please see
   [this section](#metadata) for further details.
4. **Produce Metadata Artifacts**: A transformation workflow is run on all submissions
   in the submission registry to produce multiple query-specific metadata artifacts
   using the `ghga-datasteward-kit metadata transform` command. Please see
   [this section](#metadata) for further details.
5. **Publish Metadata**: To publish all metadata artifacts of all submissions to the
   running system so that they are available on the GHGA website, the
   `ghga-datasteward-kit load` command can be used.
6. **Make Files Downloadable**: To make files downloadable, the file summary JSONs
   provided by the Local Data Steward (see [here](#b-file-encryption-and-upload)) need
   to be ingested into the running system using the
   `ghga-datasteward-kit files ingest-upload-metadata` command. Please see
   [this section](#files-ingest-upload-metadata) for further details.


## Details per Command

An overview of all commands is provided using:

```
ghga-datasteward-kit --help
```

The following paragraphs provide additional help for using the different commands.

### files (batch-)upload

*To be performed by Local Data Stewards.*

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

An overview of important information about each the upload is written to a file called
\<alias\>.json in the output directory.

It contains the following information:
1. The file alias
2. A unique identifier for the file
3. The local file path
4. A SHA256 checksum over the unencrypted content
5. MD5 checksums over all encrypted file parts
6. SHA256 checksums over all encrypted file parts
7. The file encryption/decryption secret

Attention: Keep this output file in a safe, private location.
If this file is lost, the uploaded file content becomes inaccessible.

### files ingest-upload-metadata

*To be performed by Central Data Stewards only.*

Upload all file summary JSONs (produced using the
[files (batch-)upload](#files-batch-upload) command) from the given directory to the
running system and make the corresponding files available for download.

This command requires a configuration file as described [here](./ingest_config.md).

### metadata

*To be performed by Central Data Stewards only.*

The metadata label groups metadata related commands.

Some of them require a configuration file as described [here](./metadata_config.md).

### load

*To be performed by Central Data Stewards only.*

The load command makes files and metadata available to user in the running system.

It needs a configuration parameters as described [here](./load_config.md).

### generate-credentials

A command to generate a token/hash pair for interacting with GHGA Central services.

The generated token file should not be moved to a different system and never be shared
with another user.
The token hash (**not the token*) must be shared with the GHGA Central Operation
Team. This process has to be done only once per data steward and system (if a data
steward is working with multiple compute environments, one set of credentials per
environment should be created).

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
