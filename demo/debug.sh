#!/usr/bin/env bash
set -e

export USER_SERVICE_IMAGE='vpc-sc-demo'
export USER_SERVICE_TAG_BASE='latest'
export USER_SERVICE_TAG='dev'

sudo docker build --build-arg PROD=false -t ${USER_SERVICE_IMAGE?}:${USER_SERVICE_TAG_BASE?} .
sudo docker build -t ${USER_SERVICE_IMAGE?}:${USER_SERVICE_TAG?} -f Dockerfile.dev .

sudo docker run -it -p 5001:5001 -p 3001:3001 --rm --entrypoint=/app/debug_runner.sh -v $(pwd):/app vpc-sc-demo:dev
