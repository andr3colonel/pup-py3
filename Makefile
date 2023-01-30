PWD = $(shell pwd)

SRC = src tests

pylint:
	pylint config/.pylintrc $(SRC)

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

format: isort black
lint: flake8 mypy pylint

