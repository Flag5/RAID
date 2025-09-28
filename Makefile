# RAID Security Assessment Framework Makefile

.PHONY: help build up down dry-run run pause resume approve replay verify test lint clean install dev-setup

# Configuration
COMPOSE_FILE := docker/docker-compose.dev.yaml
PYTHON := python3
PIP := pip3

# Default target
help: ## Show this help message
	@echo "RAID Security Assessment Framework"
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development Setup
install: ## Install Python dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

dev-setup: install ## Set up development environment
	@echo "Setting up development environment..."
	mkdir -p results auth roles secrets evidence
	$(PYTHON) scripts/generate_ed25519_key.py
	@echo "Development environment ready!"

# Container Management
build: ## Build all Docker containers
	docker-compose -f $(COMPOSE_FILE) build

up: ## Start all services in development mode
	docker-compose -f $(COMPOSE_FILE) up -d

down: ## Stop all services
	docker-compose -f $(COMPOSE_FILE) down

logs: ## Show container logs
	docker-compose -f $(COMPOSE_FILE) logs -f

# RAID Commands
dry-run: ## Run assessment in dry-run mode (generates plan only)
	@if [ -z "$(ROLE)" ] || [ -z "$(TARGET)" ] || [ -z "$(AUTH)" ]; then \
		echo "Usage: make dry-run ROLE=web-pentest TARGET=example.com AUTH=auth/sample.json OUT=results/"; \
		exit 1; \
	fi
	$(PYTHON) -m controller.main dry-run \
		--role roles/$(ROLE).yaml \
		--target $(TARGET) \
		--auth $(AUTH) \
		--output $(or $(OUT),results/)

run: ## Run full assessment
	@if [ -z "$(ROLE)" ] || [ -z "$(TARGET)" ] || [ -z "$(AUTH)" ]; then \
		echo "Usage: make run ROLE=web-pentest TARGET=example.com AUTH=auth/sample.json OUT=results/"; \
		exit 1; \
	fi
	$(PYTHON) -m controller.main run \
		--role roles/$(ROLE).yaml \
		--target $(TARGET) \
		--auth $(AUTH) \
		--output $(or $(OUT),results/)

pause: ## Pause running assessment
	@if [ -z "$(RUN_ID)" ]; then \
		echo "Usage: make pause RUN_ID=<run-uuid>"; \
		exit 1; \
	fi
	curl -X POST http://localhost:8000/api/runs/$(RUN_ID)/pause

resume: ## Resume paused assessment
	@if [ -z "$(RUN_ID)" ]; then \
		echo "Usage: make resume RUN_ID=<run-uuid>"; \
		exit 1; \
	fi
	curl -X POST http://localhost:8000/api/runs/$(RUN_ID)/resume

approve: ## Submit approval for assessment
	@if [ -z "$(RUN_ID)" ]; then \
		echo "Usage: make approve RUN_ID=<run-uuid> APPROVAL='Continue with scan'"; \
		exit 1; \
	fi
	curl -X POST http://localhost:8000/api/runs/$(RUN_ID)/approve \
		-H "Content-Type: application/json" \
		-d '{"approval": "$(or $(APPROVAL),approved)"}'

replay: ## Replay assessment from artifact
	@if [ -z "$(ARTIFACT)" ]; then \
		echo "Usage: make replay ARTIFACT=results/run-123.tar.gz"; \
		exit 1; \
	fi
	$(PYTHON) -m controller.main replay --artifact $(ARTIFACT)

verify: ## Verify assessment artifact
	@if [ -z "$(ARTIFACT)" ]; then \
		echo "Usage: make verify ARTIFACT=results/run-123.tar.gz"; \
		exit 1; \
	fi
	$(PYTHON) -m controller.main verify --artifact $(ARTIFACT)

# Testing
test: ## Run all tests
	pytest tests/ -v

test-unit: ## Run unit tests only
	pytest tests/test_*.py -v

test-integration: ## Run integration tests
	pytest tests/integration/ -v

test-security: ## Run security validation tests
	pytest tests/security/ -v

test-coverage: ## Run tests with coverage report
	pytest tests/ --cov=controller --cov=mcp --cov=ui --cov-report=html

# Code Quality
lint: ## Run linter and type checking
	ruff check .
	mypy controller/ mcp/ ui/ --ignore-missing-imports

format: ## Format code
	black .
	ruff check --fix .

format-check: ## Check code formatting
	black --check .
	ruff check .

# Security
security-scan: ## Run security scanning on codebase
	bandit -r controller/ mcp/ ui/
	safety check

secrets-init: ## Initialize secrets management
	$(PYTHON) scripts/setup_secrets.py

# Cleanup
clean: ## Clean up build artifacts and containers
	docker-compose -f $(COMPOSE_FILE) down -v
	docker system prune -f
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/ .coverage htmlcov/

clean-results: ## Clean up assessment results
	rm -rf results/* evidence/*

clean-all: clean clean-results ## Complete cleanup

# Development Utilities
shell: ## Open Python shell with project context
	$(PYTHON) -c "import controller, mcp, ui; print('RAID modules loaded')" && $(PYTHON)

notebook: ## Start Jupyter notebook for development
	jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser

# Docker Development
docker-shell: ## Open shell in controller container
	docker-compose -f $(COMPOSE_FILE) exec controller /bin/bash

docker-logs-controller: ## Show controller logs
	docker-compose -f $(COMPOSE_FILE) logs -f controller

docker-logs-mcp: ## Show MCP server logs
	docker-compose -f $(COMPOSE_FILE) logs -f mcp-server

# Tool Management
tools-list: ## List available tools
	$(PYTHON) -m controller.tools list

tools-validate: ## Validate all tools
	$(PYTHON) -m controller.tools validate

tools-synthesize: ## Synthesize a new tool
	@if [ -z "$(REQUIREMENTS)" ]; then \
		echo "Usage: make tools-synthesize REQUIREMENTS='Create a tool to check HTTP headers'"; \
		exit 1; \
	fi
	$(PYTHON) -m controller.synthesizer create "$(REQUIREMENTS)"

# Monitoring and Debugging
status: ## Show system status
	@echo "=== RAID System Status ==="
	@echo "Docker Services:"
	@docker-compose -f $(COMPOSE_FILE) ps
	@echo "\nRecent Runs:"
	@ls -la results/ 2>/dev/null || echo "No results found"
	@echo "\nTool Registry:"
	@$(PYTHON) -c "from mcp.registry_store import ToolRegistry; r = ToolRegistry('./tool-registry'); print(f'Registered tools: {len(r.list_tools())}')" 2>/dev/null || echo "Registry not accessible"

health-check: ## Check system health
	@echo "=== Health Check ==="
	curl -f http://localhost:8000/health || echo "MCP Server not responding"
	$(PYTHON) -c "import controller; print('Controller modules OK')"
	docker-compose -f $(COMPOSE_FILE) ps --filter "status=running" | grep -q "raid" && echo "Containers OK" || echo "Containers not running"

# Examples and Documentation
examples: ## Run example assessments
	@echo "Running example dry-run..."
	make dry-run ROLE=web-pentest TARGET=httpbin.org AUTH=auth/sample_signed_auth.json OUT=examples/

docs: ## Generate documentation
	@echo "Generating documentation..."
	@echo "See dev/ directory for comprehensive documentation"
	@ls -la dev/

# Production Targets (WARNING: Use with caution)
prod-build: ## Build production containers
	docker-compose -f docker/docker-compose.prod.yaml build

prod-deploy: ## Deploy to production (requires proper authentication)
	@echo "WARNING: This deploys to production!"
	@read -p "Are you sure? (yes/no): " confirm && [ "$$confirm" = "yes" ] || exit 1
	docker-compose -f docker/docker-compose.prod.yaml up -d

# Information
version: ## Show version information
	@echo "RAID Security Assessment Framework"
	@echo "Version: $$(git describe --tags --always 2>/dev/null || echo 'dev')"
	@echo "Commit: $$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Docker: $$(docker --version)"

env-check: ## Check environment requirements
	@echo "=== Environment Check ==="
	@which $(PYTHON) > /dev/null && echo "✓ Python found" || echo "✗ Python not found"
	@which docker > /dev/null && echo "✓ Docker found" || echo "✗ Docker not found"
	@which docker-compose > /dev/null && echo "✓ Docker Compose found" || echo "✗ Docker Compose not found"
	@[ -f requirements.txt ] && echo "✓ Requirements file found" || echo "✗ Requirements file missing"
	@[ -d auth ] && echo "✓ Auth directory found" || echo "✗ Auth directory missing (run make dev-setup)"