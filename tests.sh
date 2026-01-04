#!/bin/bash

set -eo pipefail

# Pytests
poetry run pytest -vvvv --cov=enroll --cov-report=term-missing --disable-warnings

BUNDLE_DIR="/tmp/bundle"
ANSIBLE_DIR="/tmp/ansible"
rm -rf "${BUNDLE_DIR}" "${ANSIBLE_DIR}"

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

# Install something, harvest again and diff the harvests
sudo apt-get -y install cowsay
poetry run \
	enroll harvest --out "${BUNDLE_DIR}2"
poetry run \
	enroll diff \
	--old "${BUNDLE_DIR}" \
	--new "${BUNDLE_DIR}2" \
	--format json | jq

# Ansible test
builtin cd "${ANSIBLE_DIR}"
# Lint
ansible-lint "${ANSIBLE_DIR}"

# Run
ansible-playbook playbook.yml -i "localhost," -c local --check --diff
