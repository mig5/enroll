#!/bin/bash

set -eou pipefail

poetry run python -m pytest -q tests -vvv --cov=enroll --cov-report=term-missing
