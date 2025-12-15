#!/bin/bash

set -eo pipefail

# Pytests
poetry run pytest -vvvv --cov=enroll --cov-report=term-missing --disable-warnings

BUNDLE_DIR="/tmp/bundle"
ANSIBLE_DIR="/tmp/ansible"
rm -rf "${BUNDLE_DIR}" "${ANSIBLE_DIR}"

# Generate data
poetry run \
	enroll enroll \
	  --harvest "${BUNDLE_DIR}" \
	  --out "${ANSIBLE_DIR}"

builtin cd "${ANSIBLE_DIR}" 

# Lint
ansible-lint "${ANSIBLE_DIR}" 

# Run
sudo ansible-playbook playbook.yml -i "localhost," -c local --check --diff
