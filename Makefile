# Makefile for AWS Bedrock Security Checker
# Copyright (C) 2024  Ethan Troy
# Licensed under GNU GPL v3.0 or later

.PHONY: help install install-dev build test clean release publish lint format

help:
	@echo "AWS Bedrock Security Checker - Development Commands"
	@echo "=================================================="
	@echo "make install      - Install the package locally"
	@echo "make install-dev  - Install in development mode"
	@echo "make build        - Build distribution packages"
	@echo "make test         - Run tests"
	@echo "make clean        - Remove build artifacts"
	@echo "make release      - Interactive release process"
	@echo "make publish      - Build and publish to PyPI"
	@echo "make lint         - Run code linting"
	@echo "make format       - Format code with black"

install:
	pip install .

install-dev:
	pip install -e .
	pip install build twine black pylint

build: clean
	python3 -m build
	python3 -m twine check dist/*

test:
	python3 bedrock_security_checker.py --help
	python3 bedrock_security_checker.py --learn | head -20

clean:
	rm -rf dist/ build/ *.egg-info/ __pycache__/
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

release:
	./release.sh

publish: build
	python3 -m twine upload dist/*

lint:
	@echo "Running pylint..."
	-pylint bedrock_security_checker.py || true
	@echo "\nChecking for common issues..."
	@grep -n "print(" bedrock_security_checker.py | grep -v "# noqa" || echo "✓ No debug prints found"
	@grep -n "TODO\|FIXME\|XXX" bedrock_security_checker.py || echo "✓ No TODOs found"

format:
	black bedrock_security_checker.py setup.py

# Quick version bump commands
bump-patch:
	@CURRENT=$$(python3 -c "import re; print(re.search(r'version=\"([^\"]+)\"', open('setup.py').read()).group(1))"); \
	IFS='.' read -ra PARTS <<< "$$CURRENT"; \
	NEW="$${PARTS[0]}.$${PARTS[1]}.$$(($${PARTS[2]} + 1))"; \
	sed -i.bak "s/version=\"$$CURRENT\"/version=\"$$NEW\"/" setup.py && rm setup.py.bak; \
	sed -i.bak "s/version = \"$$CURRENT\"/version = \"$$NEW\"/" pyproject.toml && rm pyproject.toml.bak; \
	echo "Bumped version from $$CURRENT to $$NEW"

bump-minor:
	@CURRENT=$$(python3 -c "import re; print(re.search(r'version=\"([^\"]+)\"', open('setup.py').read()).group(1))"); \
	IFS='.' read -ra PARTS <<< "$$CURRENT"; \
	NEW="$${PARTS[0]}.$$(($${PARTS[1]} + 1)).0"; \
	sed -i.bak "s/version=\"$$CURRENT\"/version=\"$$NEW\"/" setup.py && rm setup.py.bak; \
	sed -i.bak "s/version = \"$$CURRENT\"/version = \"$$NEW\"/" pyproject.toml && rm pyproject.toml.bak; \
	echo "Bumped version from $$CURRENT to $$NEW"

bump-major:
	@CURRENT=$$(python3 -c "import re; print(re.search(r'version=\"([^\"]+)\"', open('setup.py').read()).group(1))"); \
	IFS='.' read -ra PARTS <<< "$$CURRENT"; \
	NEW="$$(($${PARTS[0]} + 1)).0.0"; \
	sed -i.bak "s/version=\"$$CURRENT\"/version=\"$$NEW\"/" setup.py && rm setup.py.bak; \
	sed -i.bak "s/version = \"$$CURRENT\"/version = \"$$NEW\"/" pyproject.toml && rm pyproject.toml.bak; \
	echo "Bumped version from $$CURRENT to $$NEW"