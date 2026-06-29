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
ANSIBLE_JINJATURTLE_DIR="${WORK_DIR}/ansible-jinjaturtle"
ANSIBLE_NO_JINJATURTLE_DIR="${WORK_DIR}/ansible-no-jinjaturtle"
TEST_FQDN="${ENROLL_TEST_FQDN:-enroll-ci.example.test}"
JINJATURTLE_FIXTURE="${WORK_DIR}/enroll-tests-jinjaturtle.ini"
ANSIBLE_PLAYBOOK_EXTRA_ARGS=()

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

require_supported_ci_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      debian)
        if [[ "${VERSION_ID:-}" != "13" ]]; then
          printf 'WARNING: tests.sh is maintained for Debian 13 CI; detected Debian %s.\n' "${VERSION_ID:-unknown}" >&2
        fi
        ;;
      almalinux|rhel|rocky|centos|fedora)
        printf 'Detected RPM-family CI host: %s %s.\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
        ;;
      *)
        printf 'WARNING: tests.sh is maintained for Debian 13 and AlmaLinux/RHEL-family CI; detected %s %s.\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
        ;;
    esac
  fi
}


pid1_comm() {
  if [[ -r /proc/1/comm ]]; then
    tr -d '[:space:]' </proc/1/comm || true
    return
  fi
  if command -v ps >/dev/null 2>&1; then
    ps -p 1 -o comm= 2>/dev/null | tr -d '[:space:]' || true
  fi
}

configure_ansible_playbook_extra_args() {
  local pid1
  pid1="$(pid1_comm)"

  ANSIBLE_PLAYBOOK_EXTRA_ARGS=()
  if [[ "${pid1}" != "systemd" ]]; then
    section "Setup: Ansible systemd runtime guard"
    printf 'PID 1 is %s, not systemd; disabling generated Ansible systemd runtime enforcement for CI noop plays.\n' "${pid1:-unknown}"
    ANSIBLE_PLAYBOOK_EXTRA_ARGS=(-e enroll_manage_systemd_runtime=false)
  fi
}

os_id() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    printf '%s' "${ID:-unknown}"
  else
    printf 'unknown'
  fi
}

os_version_major() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    printf '%s' "${VERSION_ID%%.*}"
  else
    printf 'unknown'
  fi
}

is_debian() {
  [[ "$(os_id)" == "debian" ]]
}

is_rpm_family() {
  case "$(os_id)" in
    almalinux|rhel|rocky|centos|fedora) return 0 ;;
    *) return 1 ;;
  esac
}

pkg_update_once() {
  if is_debian; then
    if [[ -z "${APT_UPDATED:-}" ]]; then
      section "Setup: apt metadata"
      run apt-get update
      APT_UPDATED=1
    fi
  elif is_rpm_family; then
    if [[ -z "${DNF_UPDATED:-}" ]]; then
      section "Setup: dnf metadata"
      run dnf -y makecache
      DNF_UPDATED=1
    fi
  else
    fail "Unsupported package manager for OS $(os_id)."
  fi
}

translate_packages() {
  local translated=()
  local pkg
  for pkg in "$@"; do
    if is_debian; then
      translated+=("${pkg}")
      continue
    fi

    case "${pkg}" in
      ansible) translated+=(ansible-core) ;;
      apache2) translated+=(httpd) ;;
      gnupg) translated+=(gnupg2) ;;
      curl) translated+=(curl-minimal) ;;
      lsb-release) translated+=(redhat-lsb-core) ;;
      python3-apt) ;;
      python3-jsonschema) translated+=(python3-jsonschema) ;;
      python3-venv) ;;
      systemctl) translated+=(systemd) ;;
      *) translated+=("${pkg}") ;;
    esac
  done
  printf '%s\n' "${translated[@]}"
}

pkg_install() {
  local packages=()
  local pkg

  while IFS= read -r pkg; do
    [[ -n "${pkg}" ]] && packages+=("${pkg}")
  done < <(translate_packages "$@")

  if [[ "${#packages[@]}" -eq 0 ]]; then
    return 0
  fi

  pkg_update_once
  if is_debian; then
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
  elif is_rpm_family; then
    ensure_epel_repo
    run dnf -y install "${packages[@]}"
  else
    fail "Unsupported package manager for OS $(os_id)."
  fi
}

pkg_remove_purge() {
  if is_debian; then
    run env DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge "$@"
  elif is_rpm_family; then
    run dnf -y remove "$@"
  else
    fail "Unsupported package manager for OS $(os_id)."
  fi
}

ensure_epel_repo() {
  if ! is_rpm_family; then
    return
  fi
  if rpm -q epel-release >/dev/null 2>&1; then
    return
  fi
  run dnf -y install dnf-plugins-core epel-release
  run dnf -y config-manager --set-enabled crb || true
  DNF_UPDATED=
}

ensure_jinjaturtle() {
  section "Setup: JinjaTurtle package"
  if command -v jinjaturtle >/dev/null 2>&1; then
    printf 'jinjaturtle already available at: %s\n' "$(command -v jinjaturtle)"
    return
  fi

  if is_debian; then
    pkg_install ca-certificates curl gnupg lsb-release
    run mkdir -p /usr/share/keyrings
    run bash -c "curl -fsSL https://mig5.net/static/mig5.asc | gpg --dearmor --yes -o /usr/share/keyrings/mig5.gpg"

    local codename
    codename="$(lsb_release -cs)"
    run bash -c "printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/mig5.gpg] https://apt.mig5.net ${codename} main' > /etc/apt/sources.list.d/mig5.list"
    run apt-get update
    APT_UPDATED=1
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends jinjaturtle
  elif is_rpm_family; then
    printf 'Skipping JinjaTurtle package integration on RPM-family CI;\n'
    return
  else
    fail "Unsupported OS for JinjaTurtle package install: $(os_id)."
  fi
}

require_cmd() {
  local cmd="$1"
  local hint="$2"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "Required command '${cmd}' was not found. ${hint}"
  fi
}

ensure_ansible() {
  ensure_epel_repo
  if ! command -v ansible-playbook >/dev/null 2>&1 || ! command -v ansible-lint >/dev/null 2>&1; then
    pkg_install ansible ansible-lint
  fi
  require_cmd ansible-playbook "Install the ansible/ansible-core package."
  require_cmd ansible-lint "Install the ansible-lint package."
}

run_pytests() {
  section "Python unit tests"
  cd "${PROJECT_ROOT}"
  run poetry run python -m pytest -vvvv --cov=enroll --cov-report=term-missing --disable-warnings
}

prepare_harvest_fixture() {
  section "Common harvest fixture and CLI smoke checks"
  pkg_install jq apache2

  cat >"${JINJATURTLE_FIXTURE}" <<'EOF'
[enroll_tests]
enabled = true
answer = 42
EOF

  cd "${PROJECT_ROOT}"
  rm -rf "${BUNDLE_DIR}" "${BUNDLE_DIFF_DIR}"

  run poetry run enroll harvest --out "${BUNDLE_DIR}" --include-path "${JINJATURTLE_FIXTURE}"
  run poetry run enroll explain "${BUNDLE_DIR}"
  run bash -c "poetry run enroll explain '${BUNDLE_DIR}' --format json | jq"
  run poetry run enroll validate --fail-on-warnings "${BUNDLE_DIR}"

  pkg_install cowsay
  run poetry run enroll harvest --out "${BUNDLE_DIFF_DIR}" --include-path "${JINJATURTLE_FIXTURE}"
  run poetry run enroll validate --fail-on-warnings "${BUNDLE_DIFF_DIR}"
  run bash -c "poetry run enroll diff --old '${BUNDLE_DIR}' --new '${BUNDLE_DIFF_DIR}' --format json | jq"
  pkg_remove_purge cowsay
}

assert_template_files() {
  local manifest_dir="$1"
  local extension="$2"
  local expected="$3"
  local label="$4"
  local found

  found="$(find "${manifest_dir}" -type f -name "*.${extension}" -print -quit)"
  if [[ "${expected}" == "present" ]]; then
    if [[ -z "${found}" ]]; then
      fail "Expected ${label} to contain at least one .${extension} template, but none were found."
    fi
    printf 'Found expected .%s template in %s: %s\n' "${extension}" "${label}" "${found}"
  else
    if [[ -n "${found}" ]]; then
      fail "Expected ${label} to contain no .${extension} templates, but found ${found}."
    fi
    printf 'Confirmed no .%s templates in %s.\n' "${extension}" "${label}"
  fi
}

run_ansible_jinjaturtle_variant() {
  local out_dir="$1"
  local expected="$2"
  local label="$3"
  shift 3

  ensure_ansible
  cd "${PROJECT_ROOT}"
  rm -rf "${out_dir}"
  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${out_dir}" "$@"
  assert_template_files "${out_dir}" "j2" "${expected}" "${label}"
  ansible-galaxy install -r "${out_dir}/requirements.yml"
  run ansible-lint "${out_dir}"
  cd "${out_dir}"
  run ansible-playbook playbook.yml -i "localhost," -c local --check --diff "${ANSIBLE_PLAYBOOK_EXTRA_ARGS[@]}"
}

run_jinjaturtle_manifest_tests() {
  if is_rpm_family ; then
    section "JinjaTurtle integration matrix"
    printf 'Skipping JinjaTurtle package integration on RPM-family CI;\n'
    return
  fi
  ensure_jinjaturtle
  require_cmd jinjaturtle "Install JinjaTurtle before running the JinjaTurtle integration matrix."

  section "Ansible JinjaTurtle manifest noop tests"
  run_ansible_jinjaturtle_variant "${ANSIBLE_JINJATURTLE_DIR}" present "Ansible with JinjaTurtle on PATH"
  run_ansible_jinjaturtle_variant "${ANSIBLE_NO_JINJATURTLE_DIR}" absent "Ansible with --no-jinjaturtle" --no-jinjaturtle
}

run_ansible_noop_tests() {
  section "Ansible manifest noop tests"
  ensure_ansible
  cd "${PROJECT_ROOT}"
  rm -rf "${ANSIBLE_DIR}" "${ANSIBLE_NO_COMMON_DIR}" "${ANSIBLE_FQDN_DIR}"

  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${ANSIBLE_DIR}"
  ansible-galaxy install -r "${ANSIBLE_DIR}/requirements.yml"
  run ansible-lint "${ANSIBLE_DIR}"
  cd "${ANSIBLE_DIR}"
  run ansible-playbook playbook.yml -i "localhost," -c local --check --diff "${ANSIBLE_PLAYBOOK_EXTRA_ARGS[@]}"

  cd "${PROJECT_ROOT}"
  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${ANSIBLE_NO_COMMON_DIR}" --no-common-roles
  ansible-galaxy install -r "${ANSIBLE_NO_COMMON_DIR}/requirements.yml"
  cd "${ANSIBLE_NO_COMMON_DIR}"
  run ansible-playbook playbook.yml -i "localhost," -c local --check --diff "${ANSIBLE_PLAYBOOK_EXTRA_ARGS[@]}"

  cd "${PROJECT_ROOT}"
  run poetry run enroll manifest --harvest "${BUNDLE_DIR}" --out "${ANSIBLE_FQDN_DIR}" --fqdn "${TEST_FQDN}"
  ansible-galaxy install -r "${ANSIBLE_FQDN_DIR}/requirements.yml"
  cd "${ANSIBLE_FQDN_DIR}"
  run ansible-playbook "playbooks/${TEST_FQDN}.yml" -i inventory/hosts.ini -c local --limit "${TEST_FQDN}" --check --diff "${ANSIBLE_PLAYBOOK_EXTRA_ARGS[@]}"
}

main() {
  require_root
  require_supported_ci_os
  run_pytests
  prepare_harvest_fixture
  configure_ansible_playbook_extra_args
  run_ansible_noop_tests
  run_jinjaturtle_manifest_tests
}

main "$@"
