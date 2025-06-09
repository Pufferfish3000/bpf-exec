.PHONY: build format lint deps clean

all: build wheel

build:
	cmake -S . -B ./build
	cmake --build ./build	

format:
	find . -type f \( -iname "*.c" -o -iname "*.h" \) | xargs clang-format -style=file -i
	black .

lint: build
	mypy --config-file mypy.ini c2/
	@CodeChecker analyze ./build/compile_commands.json --enable sensitive --output ./codechecker
	-CodeChecker parse --export html --output ./codechecker/report ./codechecker
	firefox ./codechecker/report/index.html &

wheel:
	python3 -m build --wheel

clean:
	rm -rf ./build
	rm -rf ./codechecker
	find c2/deploy -type f ! -name "*.*" -delete

deps:
	pip install -r requirements.txt
