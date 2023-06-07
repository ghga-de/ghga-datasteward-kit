# Config


*Required options for file uploads.*


## Properties


- **`s3_endpoint_url`** *(string)*: URL of the S3 server.

- **`s3_access_key_id`** *(string)*: Access key ID for the S3 server.

- **`s3_secret_access_key`** *(string)*: Secret access key for the S3 server.

- **`bucket_id`** *(string)*: Bucket id where the encrypted, uploaded file is stored.

- **`part_size`** *(integer)*: Upload part size in MiB. Has to be between 5 and 5120. Default: `16`.

- **`output_dir`** *(string)*: Directory for the output metadata file.
