# NetGuard Makefile

.PHONY: install test clean run help

PYTHON := python3
PIP := pip3

help:
	@echo "NetGuard - Available Commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make test       - Run unit tests"
	@echo "  make run        - Run NetGuard (requires root)"
	@echo "  make clean      - Clean output files"
	@echo "  make build      - Build distribution packages"

install:
	$(PIP) install -r requirements.txt

test:
	$(PYTHON) -m pytest tests/ -v
	# Fallback to unittest if pytest not installed
	# $(PYTHON) -m unittest discover tests/ -v

run:
	sudo $(PYTHON) netguard.py

clean:
	rm -rf output/
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf build/ dist/ *.egg-info/

build:
	$(PYTHON) setup.py sdist bdist_wheel
