#!/bin/bash

docker login
docker build -t c1cs-query-update .
docker tag c1cs-query-update mawinkler/c1cs-query-update:latest
docker push mawinkler/c1cs-query-update:latest