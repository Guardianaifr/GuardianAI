# GuardianAI Test Suite Setup

## Installation Commands

Run these commands in your terminal at `f:\Saas\guardianai`:

```powershell
# Install testing dependencies
pip install pytest pytest-cov

# Verify installation
python -m pytest --version
```

## Test Directory Structure

```
f:\Saas\guardianai\
├── tests\
│   ├── __init__.py
│   ├── conftest.py              # Shared fixtures
│   ├── guardrails\
│   │   ├── __init__.py
│   │   ├── test_input_filter.py
│   │   ├── test_output_validator.py
│   │   └── test_ai_firewall.py
│   ├── runtime\
│   │   ├── __init__.py
│   │   └── test_interceptor.py
│   └── utils\
│       ├── __init__.py
│       └── test_logger.py
```

## Running Tests

```powershell
# Run all tests
pytest

# Run with coverage
pytest --cov=guardian --cov-report=term-missing

# Run specific test file
pytest tests/guardrails/test_input_filter.py

# Run with verbose output
pytest -v
```

## Coverage Goals

- **Phase 1**: 30% coverage (core guardrails)
- **Phase 2**: 60% coverage (add runtime tests)
- **Phase 3**: 80% coverage (comprehensive suite)
