#!/usr/bin/env bash
set -e

export USER_SERVICE_IMAGE='vpc-sc-demo'
export USER_SERVICE_TAG='latest'

sudo docker build --build-arg PROD=false -t ${USER_SERVICE_IMAGE?}:${USER_SERVICE_TAG?} .
sudo docker run -p 8081:8080 --rm -it ${USER_SERVICE_IMAGE?}:${USER_SERVICE_TAG?}
