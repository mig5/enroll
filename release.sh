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
    --no-cache \
    --progress=plain \
    --build-arg BASE_IMAGE=${dist} .

  docker run --rm \
    -e SUITE="${release}" \
    -v "$PWD":/src \
    -v "$PWD/dist/${release}":/out \
    enroll-deb:${release}

  debfile=$(ls -1 dist/${release}/*.deb)
  reprepro -b /home/user/git/repo includedeb "${release}" "${debfile}"
done

# RPM
sudo apt-get -y install createrepo-c rpm
BUILD_OUTPUT="${HOME}/git/enroll/dist"
KEYID="00AE817C24A10C2540461A9C1D7CDE0234DB458D"
REPO_ROOT="${HOME}/git/repo_rpm"
REMOTE="letessier.mig5.net:/opt/repo_rpm"

DISTS=(
  fedora:43
  fedora:42
)

for dist in ${DISTS[@]}; do
  release=$(echo ${dist} | cut -d: -f2)
  REPO_RELEASE_ROOT="${REPO_ROOT}/fc${release}"
  RPM_REPO="${REPO_RELEASE_ROOT}/rpm/x86_64"
  mkdir -p "$RPM_REPO"

  docker build \
    --no-cache \
    -f Dockerfile.rpmbuild \
    -t enroll-rpm:${release} \
    --progress=plain \
    --build-arg BASE_IMAGE=${dist} \
    .

  docker run --rm -v "$PWD":/src -v "$PWD/dist/rpm":/out -v "$HOME/git/jinjaturtle/dist/rpm":/deps:ro enroll-rpm:${release}
  sudo chown -R "${USER}" "$PWD/dist"

  for file in `ls -1 "${BUILD_OUTPUT}/rpm"`; do
    rpmsign --addsign "${BUILD_OUTPUT}/rpm/$file"
  done

  cp "${BUILD_OUTPUT}/rpm/"*.rpm "$RPM_REPO/"

  createrepo_c "$RPM_REPO"

  echo "==> Signing repomd.xml..."
  qubes-gpg-client --local-user "$KEYID" --detach-sign --armor "$RPM_REPO/repodata/repomd.xml" > "$RPM_REPO/repodata/repomd.xml.asc"
done

echo "==> Syncing repo to server..."
rsync -aHPvz --exclude=.git --delete "$REPO_ROOT/" "$REMOTE/"

echo "Done!"
