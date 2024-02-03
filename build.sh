docker build --platform linux/amd64 -t ghcr.io/fruel/piaros:latest-amd64 --build-arg BUILDER_TAG=x86_64-musl .
docker build --platform linux/arm64 -t ghcr.io/fruel/piaros:latest-arm64 --build-arg BUILDER_TAG=aarch64-musl .
docker build --platform linux/arm/v7 -t ghcr.io/fruel/piaros:latest-arm --build-arg BUILDER_TAG=armv7-musleabihf .

docker image save ghcr.io/fruel/piaros:latest-amd64 -o piaros-amd64.tar
docker image save ghcr.io/fruel/piaros:latest-arm64 -o piaros-arm64.tar
docker image save ghcr.io/fruel/piaros:latest-arm -o piaros-arm.tar

# docker push ghcr.io/fruel/piaros:latest-amd64
# docker push ghcr.io/fruel/piaros:latest-arm64
# docker push ghcr.io/fruel/piaros:latest-arm

# docker manifest create ghcr.io/fruel/piaros:latest \
#    --amend ghcr.io/fruel/piaros:latest-amd64 \
#    --amend ghcr.io/fruel/piaros:latest-arm64 \
#    --amend ghcr.io/fruel/piaros:latest-arm 

# docker manifest push ghcr.io/fruel/piaros:latest