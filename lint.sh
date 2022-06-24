#!/bin/bash

set -x
set -e

poetry run black --check --diff .
poetry run flake8 .
poetry run isort --check --diff --profile black .
poetry run mypy --no-incremental
