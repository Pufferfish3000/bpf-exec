.PHONY: build format lint deps

build:
	cmake -S . -B ./build
	cmake --build ./build	

format:
	find . -type f \( -iname "*.c" -o -iname "*.h" \) | xargs clang-format -style=file -i
	black .

lint: build
	mypy --config-file mypy.ini c2/
	@CodeChecker analyze ./build/compile_commands.json --enable sensitive --ignore skipfile --output ./codechecker
	-CodeChecker parse --ignore skipfile --export html --output ./codechecker/report ./codechecker
	firefox ./codechecker/report/index.html &

deps:
	pip install -r requirements.txt
