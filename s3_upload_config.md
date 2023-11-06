# Config


*Required options for file uploads.*


## Properties


- **`s3_endpoint_url`** *(string)*: URL of the local data hub's S3 server.

- **`s3_access_key_id`** *(string)*: This parameter plus the s3_secret_access_key serve as credentials for accessing the internal staging bucket (as in `bucket_id`) on the local data hub's S3 server with s3:GetObject and s3:PutObject privileges. These credentials should never be shared with GHGA Central.

- **`s3_secret_access_key`** *(string)*: Secret access key corresponding to the `s3_access_key_id`.

- **`bucket_id`** *(string)*: Bucket ID of the internal staging bucket of the local data hub's S3 systemwhere the encrypted files are uploaded to.

- **`part_size`** *(integer)*: Upload part size in MiB. Has to be between 5 and 5120. Default: `16`.

- **`output_dir`** *(string)*: Directory for the output metadata files. For each file upload one metadata file in yaml format will be generated. It contains details on the files such as checksums, the original file path, the auto generated object ID used on the S3 system, and the ID of the secret (the secret itself is automatically communicated to GHGA Central) used to encrypt the file.

- **`secret_ingest_pubkey`** *(string)*: Public key provided by GHGA Central used to encrypt the communication with GHGA Central.

- **`secret_ingest_baseurl`** *(string)*: Base URL under which the /ingest_secret endpoint is available. This is an endpoint exposed by GHGA Central. This value is provided by GHGA Central on demand.
