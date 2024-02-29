#!/usr/bin/env bash
if [ -z "$DOCKER_REPO" ]; then
 echo "DOCKER_REPO Not set"
 exit 1
fi
docker buildx create --append --name cross_builder
docker buildx use cross_builder
docker buildx inspect --bootstrap

docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

timestamp=`date +%s`
docker buildx build \
  --ulimit nofile=1024000:1024000 \
  --platform linux/amd64,linux/arm64 \
  --target=dg_fast_farmer \
  . -t $DOCKER_REPO/dg_fast_farmer:latest \
    -t $DOCKER_REPO/dg_fast_farmer:build_${timestamp} \
  --push
