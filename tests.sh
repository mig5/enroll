#!/bin/bash

set -eo pipefail

# Pytests
poetry run pytest -vvvv --cov=enroll --cov-report=term-missing --disable-warnings

BUNDLE_DIR="/tmp/bundle"
ANSIBLE_DIR="/tmp/ansible"
rm -rf "${BUNDLE_DIR}" "${ANSIBLE_DIR}"

# Install something that has symlinks like apache2,
# to extend the manifests that will be linted later
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2

# Generate data
poetry run \
	enroll single-shot \
	  --harvest "${BUNDLE_DIR}" \
	  --out "${ANSIBLE_DIR}"

# Analyse
poetry run \
	enroll explain "${BUNDLE_DIR}"
poetry run \
        enroll explain "${BUNDLE_DIR}" --format json | jq

# Validate
poetry run \
	enroll validate --fail-on-warnings "${BUNDLE_DIR}"

# Install/remove something, harvest again and diff the harvests
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cowsay
poetry run \
	enroll harvest --out "${BUNDLE_DIR}2"
# Validate
poetry run \
	enroll validate --fail-on-warnings "${BUNDLE_DIR}2"
# Diff
poetry run \
	enroll diff \
	  --old "${BUNDLE_DIR}" \
	  --new "${BUNDLE_DIR}2" \
	  --format json | jq
DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge cowsay

# Ensure some flatpaks are installed
DEBIAN_FRONTEND=noninteractive apt-get install -y flatpak
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install -y flathub org.onionshare.OnionShare

poetry run \
	enroll manifest \
	--harvest "${BUNDLE_DIR}2" \
	--out "${ANSIBLE_DIR}2"

# Test the presence of OnionShare
builtin cd "${ANSIBLE_DIR}2"
grep -r org.onionshare.OnionShare "${ANSIBLE_DIR}2/roles"
ansible-playbook playbook.yml -i "localhost," -c local --check --diff --tags role_flatpak

# Ansible test
builtin cd "${ANSIBLE_DIR}"
# Lint
ansible-lint "${ANSIBLE_DIR}"

# Run
ansible-playbook playbook.yml -i "localhost," -c local --check --diff
