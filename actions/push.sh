#!/bin/bash
set -x
set -e

source ./build.config
IMAGE=omss

docker push $PROJECT/$IMAGE:$TAG
