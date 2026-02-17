# LLM IO Guard

Extensible LLM input/output content filter

## Features

- 🚀 Modern Python 3.12 with uv package manager
- 📦 Structured project layout with src layout
- 🧪 Parallel testing with pytest-xdist
- 📝 Structured logging with structlog
- 🎨 Code formatting with black and ruff
- 🔍 Type checking with mypy and pyright
- 🛡️ Security scanning with bandit
- 📊 Test coverage reporting
- 🔧 Makefile for common tasks
- 📓 Jupyter notebooks for analysis and experimentation

## Installation

### Prerequisites

- Python 3.12 or higher
- [uv](https://github.com/astral-sh/uv) package manager

### Setup

1. Clone the repository:
```bash
git clone <your-repository-url>/llm_io_guard.git
cd llm_io_guard
```

2. Install dependencies:
```bash
make install
# or
uv sync --all-extras
```

3. Install notebook dependencies (optional):
```bash
make install-notebooks
# or
uv pip install -e ".[notebooks]"
```

## Usage

### As a Python module

```python
from llm_io_guard import hello_world
from utils import configure_logging, get_logger

# Configure logging
configure_logging(level="INFO", format="console")
logger = get_logger(__name__)

# Call hello world function
message = hello_world()
print(message)  # Hello, World!
```

### Running the example script

```bash
make run-example
# or
uv run python scripts/example_script.py
```

## Development

### Running tests

```bash
# Run all tests in parallel
make test

# Run with coverage
make test-cov

# Run only serial tests (non-thread-safe)
make test-serial
```

### Code quality

```bash
# Format code
make fmt

# Run linters
make lint

# Type checking
make type

# Check docstring coverage
make docs

# Run all checks
make dev
```

### Available Make targets

```bash
make help           # Show all available targets
make install        # Install dependencies
make test           # Run tests in parallel
make test-serial    # Run serial tests only
make test-cov       # Run tests with coverage
make fmt            # Format code
make lint           # Run all linters
make type           # Run type checking
make docs           # Check docstring coverage
make clean          # Clean temporary files
make run-example    # Run example script
make dev            # Install and run all checks
```

## Project Structure

```
llm_io_guard/
├── src/                              # Source code
│   └── llm_io_guard/
│       ├── __init__.py               # Package initialization
│       ├── __main__.py               # CLI entry point
│       ├── core.py                   # Core functionality
│       └── utils/                    # Utility modules
│           ├── __init__.py
│           └── logging.py            # Structured logging setup
├── scripts/                          # Command scripts
│   └── example_script.py             # Example uv run script
├── notebooks/                        # Jupyter notebooks
│   ├── README.md                     # Notebook usage guide
│   └── example_analysis.ipynb        # Example analysis notebook
├── tests/                            # Test suite
│   ├── __init__.py
│   ├── conftest.py                   # Pytest configuration
│   ├── test_core.py                  # Core module tests
│   └── test_utils/                   # Utils tests
│       ├── __init__.py
│       └── test_logging.py           # Logging tests
├── tmp/                              # Temporary files (gitignored)
├── pyproject.toml                    # Project configuration
├── Makefile                          # Development commands
├── .gitignore                        # Git ignore patterns
└── .python-version                   # Python version specification
```

## Logging

The project uses structured logging with `structlog`. Logs can be output in two formats:

### Console format (development)
```python
configure_logging(level="DEBUG", format="console")
logger.info("user_action", user_id=123, action="login")
# Output: 2024-01-01T12:00:00Z [info] user_action user_id=123 action=login
```

### JSON format (production)
```python
configure_logging(level="INFO", format="json")
logger.info("user_action", user_id=123, action="login")
# Output: {"timestamp": "2024-01-01T12:00:00Z", "level": "info", "event": "user_action", "user_id": 123, "action": "login"}
```

### Context management
```python
from llm_io_guard.utils import log_context

with log_context(request_id="abc-123", user_id=456):
    logger.info("processing_request")
    # All logs within this context will include request_id and user_id
```

## Notebooks

The project includes Jupyter notebooks for data analysis and experimentation.

### Starting Jupyter Lab
```bash
make notebook
# or
uv run jupyter lab --notebook-dir=notebooks
```

### Features
- Example analysis notebook with data visualization
- Integration with project modules
- Sample code for pandas, matplotlib, seaborn, and plotly
- Best practices for reproducible research

See `notebooks/README.md` for detailed documentation.

### Performance logging
```python
from llm_io_guard.utils import log_execution_time

@log_execution_time
def slow_function():
    # Function execution time will be logged automatically
    pass
```

## Testing

Tests are configured to run in parallel by default using `pytest-xdist`. For tests that need to run serially (e.g., database operations), use the `@pytest.mark.serial` decorator:

```python
@pytest.mark.serial
def test_database_operation():
    # This test will run serially
    pass
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License


This project is licensed under the MIT License.


## Author

**Bas Wenneker**
- Email: bas@headingfwd.com