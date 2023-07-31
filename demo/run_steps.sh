#!/bin/bash

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

cd /workspace/demo

mkdir -p \
    ./store/artifact_models \
    ./store/submissions \
    ./store/event_store \
    ./store/file_uploads
touch ./store/accessions.txt

echo "n65vGs4QfPjCOTrNLjnX_cFNM7z_PhmdnOLqUoizWo4" > ~/.ghga_data_steward_token.txt

curl -X PUT -H "Content-Type: application/json" \
    -H "Authorization: AWS test:test" \
    "http://localstack:4566/staging"

ghga-datasteward-kit files upload \
    --input-path ./input/files/SEQ_FILE_A_R1.fastq.gz \
    --alias SEQ_FILE_A_R1.fastq.gz \
    --config-path ./config/file_config.yaml

rm -f ./store/file_uploads/SEQ_FILE_A_R1.fastq.gz.json

ghga-datasteward-kit files batch-upload \
    --tsv ./input/files.tsv \
    --config-path ./config/file_config.yaml \
    --parallel-processes 10

ghga-datasteward-kit metadata generate-artifact-models \
    --config-path ./config/metadata_config.yaml

ghga-datasteward-kit metadata transpile ./input/metadata.xlsx ./input/metadata.json

ghga-datasteward-kit metadata submit \
    --submission-title "Test" \
    --submission-description "Test" \
    --metadata-path ./input/metadata.json \
    --config-path ./config/metadata_config.yaml

ghga-datasteward-kit metadata transform --config-path ./config/metadata_config.yaml

ghga-datasteward-kit load --config-path ./config/loader_config.yaml
