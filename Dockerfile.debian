# Copyright 2021 - 2024 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

## creating building container
FROM python:3.12-slim-bookworm AS builder
# update and install dependencies
RUN apt update
RUN apt upgrade -y
RUN pip install build
# copy code
COPY . /service
WORKDIR /service
# build wheel
RUN python -m build

# creating running container
FROM python:3.12-slim-bookworm
# update and install dependencies
RUN apt update
RUN apt upgrade -y
# copy and install requirements and wheel
WORKDIR /service
COPY --from=builder /service/lock/requirements.txt /service
RUN pip install --no-deps -r requirements.txt
RUN rm requirements.txt
COPY --from=builder /service/dist/ /service
RUN pip install --no-deps *.whl
RUN rm *.whl
# create new user and execute as that user
RUN useradd --create-home appuser
WORKDIR /home/appuser
USER appuser
# set environment
ENV PYTHONUNBUFFERED=1
# Please adapt to package name:
ENTRYPOINT ["my-microservice"]
