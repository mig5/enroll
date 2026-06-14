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

# Ansible test
builtin cd "${ANSIBLE_DIR}"
# Lint
ansible-lint "${ANSIBLE_DIR}"

# Run
ansible-playbook playbook.yml -i "localhost," -c local --check --diff

# Common simple packages mode
poetry run \
	enroll manifest \
	--harvest "${BUNDLE_DIR}2" \
	--out "${ANSIBLE_DIR}2" \
	--merge-simple-packages

builtin cd "${ANSIBLE_DIR}2"
ls "${ANSIBLE_DIR}2/roles"
ansible-playbook playbook.yml -i "localhost," -c local --check --diff
