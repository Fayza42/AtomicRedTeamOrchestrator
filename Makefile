# Atomic Red Team Attack Orchestrator Makefile

.PHONY: help setup install clean test run-vple analyze build-web run-example

# Default atomics path - adjust as needed
ATOMICS_PATH ?= ./atomic-red-team/atomics
PLATFORM ?= linux

help: ## Show this help message
	@echo "Atomic Red Team Attack Orchestrator"
	@echo "==================================="
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Initial setup (install dependencies, create directories)
	@echo "🚀 Setting up Atomic Red Team Orchestrator..."
	python setup.py

install: ## Install Python dependencies only
	@echo "📦 Installing Python dependencies..."
	pip install -r requirements.txt

clean: ## Clean output and log files
	@echo "🧹 Cleaning up..."
	rm -rf output/* logs/* __pycache__ core/__pycache__ utils/__pycache__
	find . -name "*.pyc" -delete

test: ## Test the installation
	@echo "🧪 Testing installation..."
	python -c "from core.technique_parser import TechniqueParser; print('✅ Core modules working')"

analyze: ## Analyze target platform capabilities
	@echo "🔍 Analyzing $(PLATFORM) platform capabilities..."
	python main.py --atomics $(ATOMICS_PATH) --analyze --platform $(PLATFORM)

build-web: ## Build web application attack chain
	@echo "🌐 Building web application attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform $(PLATFORM) --export powershell

build-privesc: ## Build privilege escalation chain
	@echo "⬆️ Building privilege escalation chain..."
	python main.py --atomics $(ATOMICS_PATH) --build privilege_escalation --platform $(PLATFORM)

build-lateral: ## Build lateral movement chain
	@echo "↔️ Building lateral movement chain..."
	python main.py --atomics $(ATOMICS_PATH) --build lateral_movement --platform $(PLATFORM)

list-techniques: ## List available techniques for platform
	@echo "📋 Listing $(PLATFORM) techniques..."
	python main.py --atomics $(ATOMICS_PATH) --list --platform $(PLATFORM)

search: ## Search techniques (usage: make search TERM="privilege escalation")
	@echo "🔍 Searching for: $(TERM)"
	python main.py --atomics $(ATOMICS_PATH) --search "$(TERM)"

run-vple: ## Run VPLE VM attack example
	@echo "🎯 Running VPLE VM attack example..."
	cd examples && python vple_attack_example.py

dry-run-web: ## Execute web attack chain in dry-run mode
	@echo "🧪 Dry run: Web application attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform $(PLATFORM) --execute --dry-run

execute-web: ## Execute web attack chain (REAL EXECUTION!)
	@echo "⚠️  REAL EXECUTION: Web application attack chain..."
	@echo "Are you sure? This will execute real attack techniques!"
	@read -p "Type 'yes' to continue: " confirm && [ "$$confirm" = "yes" ]
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform $(PLATFORM) --execute

# VPLE-specific commands
vple-recon: ## VPLE VM reconnaissance phase
	@echo "🔍 VPLE Reconnaissance..."
	python main.py --atomics $(ATOMICS_PATH) --analyze --platform linux

vple-web-attack: ## Build VPLE web attack chain
	@echo "🌐 Building VPLE web attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform linux --avoid-elevation --export powershell

vple-privesc: ## Build VPLE privilege escalation
	@echo "⬆️ Building VPLE privilege escalation..."
	python main.py --atomics $(ATOMICS_PATH) --build privilege_escalation --platform linux

vple-full-chain: ## Build complete VPLE attack chain
	@echo "🎯 Building complete VPLE attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build full_compromise --platform linux --export powershell

# Development commands
dev-setup: ## Setup development environment
	pip install -r requirements.txt
	pip install pytest black flake8 mypy

test-code: ## Run code tests
	pytest tests/ -v

format-code: ## Format code with black
	black core/ utils/ *.py

lint-code: ## Lint code
	flake8 core/ utils/ *.py
	mypy core/ utils/

# Docker commands (optional)
docker-build: ## Build Docker image
	docker build -t atomic-orchestrator .

docker-run: ## Run in Docker container
	docker run -it -v $(PWD)/atomic-red-team:/app/atomic-red-team atomic-orchestrator

# Documentation
docs: ## Generate documentation
	@echo "📖 Generating documentation..."
	@echo "See README.md for complete documentation"

check-atomics: ## Check if Atomic Red Team is available
	@if [ -d "$(ATOMICS_PATH)" ]; then \
		echo "✅ Atomic Red Team found at $(ATOMICS_PATH)"; \
	else \
		echo "❌ Atomic Red Team not found at $(ATOMICS_PATH)"; \
		echo "Download with: git clone https://github.com/redcanaryco/atomic-red-team.git"; \
	fi

check-invoke: ## Check if Invoke-AtomicTest is available (Windows)
	@echo "🔍 Checking Invoke-AtomicTest availability..."
	@powershell.exe -Command "Get-Module -ListAvailable -Name invoke-atomicredteam" 2>/dev/null || echo "❌ Invoke-AtomicTest not found (install with: Install-Module invoke-atomicredteam)"

# Examples
example-full: ## Run complete example workflow
	make analyze PLATFORM=linux
	make build-web PLATFORM=linux
	make dry-run-web PLATFORM=linux

# Safety checks
safety-check: ## Perform safety checks before execution
	@echo "🛡️ Safety Check:"
	@echo "   • Are you in an isolated lab environment? (y/n)"
	@echo "   • Do you have proper backups? (y/n)"
	@echo "   • Have you reviewed the attack chain? (y/n)"
	@echo "   • Are you authorized to test this system? (y/n)"
	@echo ""
	@echo "Only proceed if you answered 'yes' to all questions!"

# Show current configuration
show-config: ## Show current configuration
	@echo "🔧 Current Configuration:"
	@echo "   ATOMICS_PATH: $(ATOMICS_PATH)"
	@echo "   PLATFORM: $(PLATFORM)"
	@echo "   Output directory: ./output/"
	@echo "   Logs directory: ./logs/"
