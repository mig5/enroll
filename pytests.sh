#!/bin/bash

set -eou pipefail

poetry run pytest -q tests -vvv --cov=enroll --cov-report=term-missing
