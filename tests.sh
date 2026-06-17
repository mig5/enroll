#!/bin/bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_PARENT="${TMPDIR:-/tmp}"
KEEP_WORKDIR=0
if [[ -n "${ENROLL_TEST_WORKDIR:-}" ]]; then
  WORK_DIR="${ENROLL_TEST_WORKDIR}"
  KEEP_WORKDIR=1
  mkdir -p "${WORK_DIR}"
else
  WORK_DIR="$(mktemp -d "${TMP_PARENT%/}/enroll-tests.XXXXXX")"
fi

BUNDLE_DIR="${WORK_DIR}/bundle"
BUNDLE_DIFF_DIR="${WORK_DIR}/bundle-diff"
ANSIBLE_DIR="${WORK_DIR}/ansible"
ANSIBLE_NO_COMMON_DIR="${WORK_DIR}/ansible-no-common"
ANSIBLE_FQDN_DIR="${WORK_DIR}/ansible-fqdn"
PUPPET_DIR="${WORK_DIR}/puppet"
PUPPET_FQDN_DIR="${WORK_DIR}/puppet-fqdn"
TEST_FQDN="${ENROLL_TEST_FQDN:-enroll-ci.example.test}"

cleanup() {
  if [[ "${KEEP_WORKDIR}" -eq 0 ]]; then
    rm -rf "${WORK_DIR}"
  else
    printf '\nKeeping ENROLL_TEST_WORKDIR: %s\n' "${WORK_DIR}"
  fi
}
trap cleanup EXIT

section() {
  printf '\n================================================================================\n'
  printf '%s\n' "$1"
  printf '================================================================================\n'
}

run() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
  "$@"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    fail "tests.sh must be run as root so harvest and CM noop tests can inspect/apply system state."
  fi
}

require_debian_ci() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "debian" || "${VERSION_ID:-}" != "13" ]]; then
      printf 'WARNING: tests.sh is maintained for Debian 13 CI; detected %s %s.\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
    fi
  fi
}

apt_update_once() {
  if [[ -z "${APT_UPDATED:-}" ]]; then
    section "Setup: apt metadata"
    run apt-get update
    APT_UPDATED=1
  fi
}

apt_install() {
  apt_update_once
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

apt_remove_purge() {
  run env DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge "$@"
}

require_cmd() {
  local cmd="$1"
  local hint="$2"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "Required command '${cmd}' was not found. ${hint}"
  fi
}

ensure_ansible() {
  if ! command -v ansible-playbook >/dev/null 2>&1 || ! command -v ansible-lint >/dev/null 2>&1; then
    apt_install ansible ansible-lint
  fi
  require_cmd ansible-playbook "Install the Debian ansible package."
  require_cmd ansible-lint "Install the Debian ansible-lint package."
}

ensure_puppet() {
  if ! command -v puppet >/dev/null 2>&1; then
    apt_install puppet || apt_install puppet-agent
  fi
  require_cmd puppet "Install Puppet before running the Puppet noop integration tests."
}

run_pytests() {
  section "Python unit tests"
  cd "${PROJECT_ROOT}"
  run poetry run pytest -vvvv --cov=enroll --cov-report=term-missing --disable-warnings
}

prepare_harvest_fixture() {
  section "Common harvest fixture and CLI smoke checks"
  apt_install jq apache2

  cd "${PROJECT_ROOT}"
  rm -rf "${BUNDLE_DIR}" "${BUNDLE_DIFF_DIR}"

  run poetry run enroll harvest --out "${BUNDLE_DIR}"
  run poetry run enroll explain "${BUNDLE_DIR}"
  run bash -c "poetry run enroll explain '${BUNDLE_DIR}' --format json | jq"
  run poetry run enroll validate --fail-on-warnings "${BUNDLE_DIR}"

  apt_install cowsay
  run poetry run enroll harvest --out "${BUNDLE_DIFF_DIR}"
  run poetry run enroll validate --fail-on-warnings "${BUNDLE_DIFF_DIR}"
  run bash -c "poetry run enroll diff --old '${BUNDLE_DIR}' --new '${BUNDLE_DIFF_DIR}' --format json | jq"
  apt_remove_purge cowsay
}

run_ansible_noop_tests() {
  section "Ansible manifest noop tests"
  ensure_ansible
  cd "${PROJECT_ROOT}"
  rm -rf "${ANSIBLE_DIR}" "${ANSIBLE_NO_COMMON_DIR}" "${ANSIBLE_FQDN_DIR}"

  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${ANSIBLE_DIR}" --target ansible
  run ansible-lint "${ANSIBLE_DIR}"
  cd "${ANSIBLE_DIR}"
  run ansible-playbook playbook.yml -i "localhost," -c local --check --diff

  cd "${PROJECT_ROOT}"
  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${ANSIBLE_NO_COMMON_DIR}" --target ansible --no-common-roles
  cd "${ANSIBLE_NO_COMMON_DIR}"
  run ansible-playbook playbook.yml -i "localhost," -c local --check --diff

  cd "${PROJECT_ROOT}"
  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${ANSIBLE_FQDN_DIR}" --target ansible --fqdn "${TEST_FQDN}"
  cd "${ANSIBLE_FQDN_DIR}"
  run ansible-playbook "playbooks/${TEST_FQDN}.yml" -i inventory/hosts.ini -c local --limit "${TEST_FQDN}" --check --diff
}

run_puppet_noop_tests() {
  section "Puppet manifest noop tests"
  ensure_puppet
  cd "${PROJECT_ROOT}"
  rm -rf "${PUPPET_DIR}" "${PUPPET_FQDN_DIR}"

  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${PUPPET_DIR}" --target puppet
  run puppet apply --modulepath "${PUPPET_DIR}/modules" "${PUPPET_DIR}/manifests/site.pp" --noop

  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${PUPPET_FQDN_DIR}" --target puppet --fqdn "${TEST_FQDN}"
  run puppet apply \
    --modulepath "${PUPPET_FQDN_DIR}/modules" \
    --hiera_config "${PUPPET_FQDN_DIR}/hiera.yaml" \
    --certname "${TEST_FQDN}" \
    "${PUPPET_FQDN_DIR}/manifests/site.pp" \
    --noop
}

main() {
  require_root
  require_debian_ci
  run_pytests
  prepare_harvest_fixture
  run_ansible_noop_tests
  run_puppet_noop_tests
}

main "$@"
