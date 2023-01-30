PWD = $(shell pwd)

pylint:
	pylint config/.pylintrc src

mypy:
	mypy --version
	mypy src

flake8:
	flake8 --version
	flake8 src

black:
	black src

isort:
	isort src --atomic

format: isort black
lint: flake8 mypy pylint

