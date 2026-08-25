# pychat — see README.md for the full story.
.DEFAULT_GOAL := help

PYTHON      ?= python3
VENV        := .venv
BIN         := $(VENV)/bin
VERSION     := $(shell grep -m1 '^version' pyproject.toml | cut -d'"' -f2)
IMAGE       := darerelaqz1/chat-app
PLATFORM    := linux/amd64

.PHONY: help install run-server run-client run-client-headless test lint fmt check \
        wire-proof sniff-test docker-build docker-push deploy teardown clean

help: ## Show this help
	@echo "pychat $(VERSION)"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "The server needs PYCHAT_ROOM_PASSWORD. Put it in .env (gitignored)."

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

install: $(BIN)/python ## Create the venv and install the project with dev extras
	$(BIN)/pip install -e ".[dev]"
	@echo
	@echo "Done. On Ubuntu the GUI also needs Tk: sudo apt install python3-tk"

run-server: ## Run the server locally (reads .env)
	@test -f .env || { echo "No .env found. Copy .env.example to .env and set PYCHAT_ROOM_PASSWORD."; exit 1; }
	set -a && . ./.env && set +a && \
	PYCHAT_DATA_DIR=$${PYCHAT_DATA_DIR:-./data} $(BIN)/python -m pychat.server

run-client: ## Run the desktop client
	$(BIN)/python -m pychat.client

run-client-headless: ## Run the terminal client (no display needed)
	$(BIN)/python -m pychat.client --headless

test: ## Run the test suite
	$(BIN)/python -m pytest -q

lint: ## Check formatting and lint rules
	$(BIN)/ruff check src tests scripts
	$(BIN)/ruff format --check src tests scripts

fmt: ## Apply formatting and safe lint fixes
	$(BIN)/ruff check --fix src tests scripts
	$(BIN)/ruff format src tests scripts

check: lint test ## Lint and test

wire-proof: ## Prove nothing leaks on the wire (no root needed)
	$(BIN)/python scripts/wire_proof.py

sniff-test: ## The tcpdump version of the wire proof (needs sudo)
	sudo ./scripts/sniff_test.sh

docker-build: ## Build both images for linux/amd64
	docker build --platform $(PLATFORM) -f docker/Dockerfile.server -t $(IMAGE):server-$(VERSION) .
	docker tag $(IMAGE):server-$(VERSION) $(IMAGE):server-latest
	docker build --platform $(PLATFORM) -f docker/Dockerfile.client -t $(IMAGE):client-$(VERSION) .
	docker tag $(IMAGE):client-$(VERSION) $(IMAGE):client-latest

docker-push: ## Push all four tags to Docker Hub
	docker push $(IMAGE):server-$(VERSION)
	docker push $(IMAGE):server-latest
	docker push $(IMAGE):client-$(VERSION)
	docker push $(IMAGE):client-latest

deploy: ## Deploy the server to AWS (creates billable resources)
	./deploy/aws_deploy.sh

teardown: ## Destroy the AWS resources
	./deploy/aws_teardown.sh

clean: ## Remove build artefacts and caches
	rm -rf build dist .pytest_cache .ruff_cache **/__pycache__ src/*.egg-info
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
