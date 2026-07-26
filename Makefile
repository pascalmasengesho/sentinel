.PHONY: install format lint typecheck test check build check-dist release-preflight docker-build snap

install:
	python -m pip install -e ".[dev]"

format:
	python -m black sentinel tests

lint:
	python -m ruff check sentinel tests

typecheck:
	python -m mypy sentinel

test:
	python -m pytest

check: lint typecheck test

build:
	python -m pip install --upgrade build twine
	python -m build

check-dist: build
	python -m twine check dist/*

release-preflight: check check-dist
	python scripts/release_preflight.py --dist dist

docker-build:
	docker build --tag sentinel-bounty:local .

snap:
	snapcraft pack

run:
	python -m sentinel --help
