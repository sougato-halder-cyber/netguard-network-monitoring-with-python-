# Contributing to NetGuard

Thank you for your interest in contributing to NetGuard! This document provides guidelines for contributing.

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/netguard.git`
3. Install dependencies: `pip install -r requirements.txt`
4. Install dev dependencies: `pip install pytest pytest-cov flake8 black`

## Code Style

- Follow PEP 8 guidelines
- Use black for code formatting: `black netguard.py`
- Run flake8 before committing: `flake8 netguard.py`

## Testing

- Write unit tests for new features
- Run tests before submitting: `python -m pytest tests/ -v`
- Aim for >80% code coverage

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes with clear commit messages
3. Add tests for new functionality
4. Update documentation if needed
5. Submit a pull request with a clear description

## Reporting Issues

When reporting issues, please include:
- Operating system and version
- Python version
- Steps to reproduce
- Expected vs actual behavior
- Error messages or logs

## Security Issues

Please do not report security issues publicly. Email security@example.com instead.
