#!/bin/bash

poetry run pytest -vvvv --cov=enroll --cov-report=term-missing --disable-warnings

poetry run enroll enroll --harvest /tmp/bundle --out /tmp/ansible && \
	cd /tmp/ansible && \
	sudo ansible-playbook playbook.yml -i "localhost," -c local --check --diff

