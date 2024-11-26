# Config


*Required options for file uploads.*


## Properties

- **`object_storages`** *(object)*: Configuration for one specific object storage node and one bucket in it. Contains additional properties.
  - **Additional properties**: Refer to *[#/$defs/S3ObjectStorageNodeConfig](#%24defs/S3ObjectStorageNodeConfig)*.

- **`part_size`** *(integer)*: Upload part size in MiB. Has to be between 5 and 5120. Default: `16`.

- **`output_dir`** *(string, format: path)*: Directory for the output metadata files. For each file upload one metadata file in yaml format will be generated. It contains details on the files such as checksums, the original file path, the auto generated object ID used on the S3 system, and the ID of the secret (the secret itself is automatically communicated to GHGA Central) used to encrypt the file.

- **`secret_ingest_pubkey`** *(string)*: Public key provided by GHGA Central used to encrypt the communication with GHGA Central.

- **`secret_ingest_baseurl`** *(string)*: Base URL under which the /ingest_secret endpoint is available. This is an endpoint exposed by GHGA Central. This value is provided by GHGA Central on demand.

- **`selected_storage_alias`** *(string)*: Alias of the selected storage node/location. Has to match the backend configuration and must also be present in the local storage configuration. During the later ingest phase, the alias will be validated by the File Ingest Service.

- **`client_max_parallel_transfers`** *(integer)*: Maximum number of parallel transfer tasks for file parts. Exclusive minimum: 0. Default: 10.

## Definitions

- <a id="$defs/S3Config"></a>**`S3Config`** *(object)*: S3 server specific config params.

  - **`s3_access_key_id`** *(string, format: password)*: This parameter plus the s3_secret_access_key serve as credentials for accessing the internal staging bucket (as in `bucket_id`) on the local data hub's S3 server with s3:GetObject and s3:PutObject privileges. These credentials should never be shared with GHGA Central.

  - **`s3_secret_access_key`** *(string, format: password)*: Secret access key corresponding to the `s3_access_key_id`.


- <a id="$defs/S3ObjectStorageNodeConfig"></a>**`S3ObjectStorageNodeConfig`** *(object)*: Configuration for one specific object storage node and one bucket in it.

  - **`bucket_id`** *(string)*: Bucket ID of the internal staging bucket of the local data hub's S3 systemwhere the encrypted files are uploaded to.

  - **`credentials`**: Refer to *[#/$defs/S3Config](#%24defs/S3Config)*.
