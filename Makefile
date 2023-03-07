message="changes"

format:
	poetry run black -l 120 timberlake/

.PHONY: dist
dist:
	rm dist/*
	poetry build -f wheel

git:
	$(eval branch := $(shell git branch --show-current))
	git add .
	git commit -a -m "$(message)"
	git push origin $(branch)

push: format git

