#!/usr/bin/env bash
docker build -t dcos-oauth-build -f JenkinsDockerfile .
docker run --rm -it -u 1000:1000 -w /go/src/github.com/dcos/dcos-oauth/ -v /var/run/docker.sock:/var/run/docker.sock -v $(PWD):/go/src/github.com/dcos/dcos-oauth/ --net=host dcos-oauth-build make test
