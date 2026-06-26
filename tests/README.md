# GuardianAI Test Suite Setup

## Installation Commands

Run these commands in your terminal at `f:\Saas\guardianai-basic-launch`:

```powershell
# Create Python 3.12 virtual environment (once)
py -3.12 -m venv .venv312

# Install dependencies
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt

# Verify installation
.\.venv312\Scripts\python.exe -m pytest --version
```

## Running Tests

```powershell
# Run all tests
.\.venv312\Scripts\python.exe -m pytest

# Run with coverage
.\.venv312\Scripts\python.exe -m pytest --cov=guardian --cov-report=term-missing

# Run specific test file
.\.venv312\Scripts\python.exe -m pytest tests/guardrails/test_input_filter.py

# Run with verbose output
.\.venv312\Scripts\python.exe -m pytest -v
```

## Coverage Goals

- **Level 1**: 30% coverage (core guardrails)
- **Level 2**: 60% coverage (add runtime tests)
- **Level 3**: 80% coverage (comprehensive suite)
