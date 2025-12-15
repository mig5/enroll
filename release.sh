#!/bin/bash

set -eo pipefail

# Clean caches etc
filedust -y .

# Publish to Pypi
poetry build
poetry publish

# Make AppImage
poetry run pyproject-appimage
mv Enroll.AppImage dist/

# Sign packages
for file in `ls -1 dist/`; do qubes-gpg-client --batch  --armor --detach-sign dist/$file > dist/$file.asc; done

# Deb stuff
DISTS=(
  debian:bookworm
  debian:trixie
  ubuntu:jammy
  ubuntu:noble
)

for dist in ${DISTS[@]}; do
  release=$(echo ${dist} | cut -d: -f2)
  mkdir -p dist/${release}

  docker build -f Dockerfile.debbuild -t enroll-deb:${release} \
    --progress=plain \
    --build-arg BASE_IMAGE=${dist} .

  docker run --rm \
    -e SUITE="${release}" \
    -v "$PWD":/src \
    -v "$PWD/dist/${release}":/out \
    enroll-deb:${release}

  # rename the file
  debfile=$(ls -1 dist/${release}/*.deb)

  reprepro -b /home/user/git/repo includedeb "${release}" "${debfile}"
done
