.PHONY: help install test test-serial test-cov fmt lint type docs clean dev build publish-test publish clean-dist

help:  ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install:  ## Install project dependencies including notebook extras with uv and editable install
	uv venv
	uv pip install -e . && uv sync --all-extras

test:  ## Run tests in parallel
	uv run pytest

test-serial:  ## Run serial tests only (non-thread-safe)
	uv run pytest -m serial

test-cov:  ## Run tests with coverage report
	uv run pytest --cov=src/llm_io_guard --cov-report=term-missing --cov-report=html

fmt:  ## Format code with ruff
	uv run ruff format src tests
	uv run ruff check --fix src tests

lint:  ## Run all linters
	uv run ruff check src tests
	uv run mypy src
	uv run bandit -r src
	uv run pyright src

typecheck:  ## Run type checking with pyright
	uv run pyright src

docs:  ## Check docstring coverage
	uv run interrogate -v src

clean:  ## Clean temporary files
	rm -rf tmp/* .pytest_cache .coverage htmlcov .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

dev:  ## Install and run development checks
	$(MAKE) install
	$(MAKE) fmt
	$(MAKE) lint
	$(MAKE) docs
	$(MAKE) test

build: clean-dist  ## Build sdist and wheel
	uv run python -m build

publish-test:  ## Upload to TestPyPI
	uv run twine upload --repository testpypi dist/*

publish:  ## Upload to PyPI
	uv run twine upload dist/*

clean-dist:  ## Clean build artifacts
	rm -rf dist/ build/ src/*.egg-info
