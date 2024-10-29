# IngestConfig


*Config options for calling the file ingest endpoint*


## Properties


- **`submission_store_dir`** *(string, format: path)*: The directory where the submission JSONs will be stored.

- **`file_ingest_baseurl`** *(string)*: Base URL under which the /ingest endpoint is available. This is an endpoint exposed by GHGA Central. This value is provided by GHGA Central on demand.

- **`file_ingest_federated_endpoint`** *(string)*: Path to the FIS endpoint (relative to baseurl) expecting the new style"+" upload metadata including a secret ID instead of the actual secret.

- **`file_ingest_legacy_endpoint`** *(string)*: Path to the FIS endpoint (relative to baseurl) expecting the old style"+"upload metadata including the encryption secret.

- **`file_ingest_pubkey`** *(string)*: Public key provided by GHGA Central used to encrypt the communication with GHGA Central.

- **`input_dir`** *(string, format: path)*: Path to directory containing output files from the upload/batch_upload command.

- **`map_files_fields`** *(array)*: Names of the accession map fields for looking up the alias->accession mapping. Default: `["study_files"]`.

  - **Items** *(string)*

- **`selected_storage_alias`** *(string)*: Alias of the selected storage node/location. Has to match the backend configuration and must also be present in the local storage configuration. During the later ingest phase, the alias will be validated by the File Ingest Service.

- **`fallback_bucket_id`** *(string)*: Fallback bucket_id for older output metadata files that don't contain a bucket ID.
