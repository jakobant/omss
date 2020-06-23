#!/bin/bash
set -x
set -e

source ./build.config
IMAGE=omss

docker build . --tag $PROJECT/$IMAGE:$TAG

