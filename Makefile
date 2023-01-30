PWD = $(shell pwd)

SRC = src tests

pylint:
	pylint $(SRC)

mypy:
	mypy --version
	mypy $(SRC)

flake8:
	flake8 --version
	flake8 $(SRC)

black:
	black $(SRC)

isort:
	isort $(SRC) --atomic

test:
	python -m coverage run --source=src -m pytest
	python -m coverage report

build: format lint test

format: isort black
lint: flake8 mypy pylint

