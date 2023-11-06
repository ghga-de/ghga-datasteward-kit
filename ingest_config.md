# IngestConfig


*Config options for calling the file ingest endpoint*


## Properties


- **`submission_store_dir`** *(string)*: The directory where the submission JSONs will be stored.

- **`file_ingest_baseurl`** *(string)*: Base URL under which the /ingest endpoint is available. This is an endpoint exposed by GHGA Central. This value is provided by GHGA Central on demand.

- **`file_ingest_pubkey`** *(string)*: Public key provided by GHGA Central used to encrypt the communication with GHGA Central.

- **`input_dir`** *(string)*: Path to directory containing output files from the upload/batch_upload command.

- **`map_files_fields`** *(array)*: Names of the accession map fields for looking up the alias->accession mapping. Default: `['study_files']`.

  - **Items** *(string)*
