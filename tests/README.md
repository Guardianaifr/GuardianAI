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
â”œâ”€â”€ tests\
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ conftest.py              # Shared fixtures
â”‚   â”œâ”€â”€ guardrails\
â”‚   â”‚   â”œâ”€â”€ __init__.py
â”‚   â”‚   â”œâ”€â”€ test_input_filter.py
â”‚   â”‚   â”œâ”€â”€ test_output_validator.py
â”‚   â”‚   â””â”€â”€ test_ai_firewall.py
â”‚   â”œâ”€â”€ runtime\
â”‚   â”‚   â”œâ”€â”€ __init__.py
â”‚   â”‚   â””â”€â”€ test_interceptor.py
â”‚   â””â”€â”€ utils\
â”‚       â”œâ”€â”€ __init__.py
â”‚       â””â”€â”€ test_logger.py
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

- **Level 1**: 30% coverage (core guardrails)
- **Level 2**: 60% coverage (add runtime tests)
- **Level 3**: 80% coverage (comprehensive suite)

