# Contributing to llm_io_guard

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/headingfwd/llm-io-guard.git
cd llm-io-guard
```

2. Install dependencies (requires Python 3.12+ and [uv](https://github.com/astral-sh/uv)):
```bash
make install
```

3. Download the spaCy model for Dutch NER:
```bash
python -m spacy download nl_core_news_lg
```

## Running Tests

```bash
# Run all tests in parallel
make test

# Run tests with coverage report
make test-cov

# Run only serial tests (non-thread-safe)
make test-serial

# Run adversarial tests
uv run pytest -m adversarial
```

## Code Style

This project uses the following tools for code quality:

- **ruff** for linting and formatting
- **mypy** and **pyright** for type checking
- **bandit** for security scanning
- **interrogate** for docstring coverage

Run all checks:
```bash
# Format code
make fmt

# Run all linters
make lint

# Type checking
make typecheck

# Check docstring coverage
make docs

# Run everything (install + format + lint + docs + test)
make dev
```

All public classes and methods should have Google-style docstrings with type hints.

## Adding a New Scanner

To add a new scanner, extend the `Scanner` abstract base class:

```python
from llm_io_guard.scanner import Scanner
from llm_io_guard.models import Action, ScanResult


class MyScanner(Scanner):
    @property
    def name(self) -> str:
        return "my_scanner"

    @property
    def tier(self) -> int:
        return 2  # 1=fast/deterministic, 2=ML/pattern, 3=LLM

    async def initialize(self) -> None:
        # Load models or resources here
        pass

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        # Implement your scanning logic
        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=0.0,
            description="Content is safe",
        )
```

Then register it with the pipeline:
```python
pipeline.register_scanner(MyScanner())
```

Add the scanner configuration to `config/default.yaml` and write tests in `tests/scanners/`.

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Ensure all tests pass (`make test`)
4. Ensure code quality checks pass (`make lint`)
5. Update documentation if needed
6. Open a pull request with a clear description of the changes
