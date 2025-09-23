#!/usr/bin/env bash

docker build -t netutils .
docker run --rm -it -v "$PWD":/app -w /app netutils sh

