# AI Gateway PoC - Makefile for Docker Operations
.PHONY: help build dev prod test clean logs shell

# Default target
help: ## Display this help message
	@echo "AI Gateway PoC - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development commands
dev: ## Start development environment with hot reload
	@echo "Starting development environment..."
	docker-compose up --build

dev-d: ## Start development environment in background
	@echo "Starting development environment in background..."
	docker-compose up -d --build

dev-logs: ## Show logs for development environment
	docker-compose logs -f

dev-stop: ## Stop development environment
	@echo "Stopping development environment..."
	docker-compose down

dev-restart: ## Restart development environment
	@echo "Restarting development environment..."
	docker-compose restart

# Production commands
prod: ## Start production environment
	@echo "Starting production environment..."
	docker-compose -f docker-compose.prod.yml up --build

prod-d: ## Start production environment in background
	@echo "Starting production environment in background..."
	docker-compose -f docker-compose.prod.yml up -d --build

prod-logs: ## Show logs for production environment
	docker-compose -f docker-compose.prod.yml logs -f

prod-stop: ## Stop production environment
	@echo "Stopping production environment..."
	docker-compose -f docker-compose.prod.yml down

# Build commands
build: ## Build all Docker images
	@echo "Building all Docker images..."
	docker-compose build

build-backend: ## Build only the Go backend image
	@echo "Building Go backend image..."
	docker build -t ai-gateway-backend .

build-frontend: ## Build only the Next.js frontend image
	@echo "Building Next.js frontend image..."
	docker build -t ai-gateway-frontend ./web

# Database commands
db-start: ## Start only database services
	@echo "Starting database services..."
	docker-compose up -d postgres redis

db-stop: ## Stop database services
	@echo "Stopping database services..."
	docker-compose stop postgres redis

db-reset: ## Reset database (WARNING: This will delete all data)
	@echo "Resetting database..."
	docker-compose down -v
	docker volume rm ai-gateway-poc_postgres_data ai-gateway-poc_redis_data 2>/dev/null || true

# Monitoring commands
monitoring: ## Start development environment with monitoring
	@echo "Starting development environment with monitoring..."
	docker-compose --profile monitoring up --build

monitoring-d: ## Start development environment with monitoring in background
	@echo "Starting development environment with monitoring in background..."
	docker-compose --profile monitoring up -d --build

# Testing commands
test: ## Run tests
	@echo "Running tests..."
	docker-compose exec gateway go test ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	docker-compose exec gateway go test -cover ./...

# Utility commands
shell-backend: ## Open shell in backend container
	docker-compose exec gateway sh

shell-frontend: ## Open shell in frontend container
	docker-compose exec web sh

shell-db: ## Open PostgreSQL shell
	docker-compose exec postgres psql -U gateway_user -d ai_gateway

shell-redis: ## Open Redis CLI
	docker-compose exec redis redis-cli

# Logs commands
logs: ## Show logs for all services
	docker-compose logs -f

logs-backend: ## Show logs for backend service
	docker-compose logs -f gateway

logs-frontend: ## Show logs for frontend service
	docker-compose logs -f web

logs-db: ## Show logs for database services
	docker-compose logs -f postgres redis

# Clean up commands
clean: ## Clean up containers and images
	@echo "Cleaning up containers and images..."
	docker-compose down --rmi all --volumes --remove-orphans

clean-all: ## Clean up everything including volumes
	@echo "Cleaning up everything including volumes..."
	docker-compose down --rmi all --volumes --remove-orphans
	docker system prune -a --volumes -f

# Health check commands
health: ## Check health of all services
	@echo "Checking health of services..."
	@echo "Backend health:"
	@curl -s http://localhost:8080/api/v1/health || echo "Backend not responding"
	@echo ""
	@echo "Frontend health:"
	@curl -s http://localhost:3000 >/dev/null && echo "Frontend is responding" || echo "Frontend not responding"
	@echo ""
	@echo "Database health:"
	@docker-compose exec -T postgres pg_isready -U gateway_user -d ai_gateway || echo "Database not responding"
	@echo ""
	@echo "Redis health:"
	@docker-compose exec -T redis redis-cli ping || echo "Redis not responding"

# Setup commands
setup: ## Setup development environment (copy env file, etc.)
	@echo "Setting up development environment..."
	@if [ ! -f .env ]; then \
		cp env.example .env; \
		echo "Created .env file from env.example"; \
		echo "Please update .env with your actual values"; \
	else \
		echo ".env file already exists"; \
	fi

# Status commands
status: ## Show status of all containers
	@echo "Container status:"
	docker-compose ps

ps: status ## Alias for status

# Update commands
update: ## Pull latest images and rebuild
	@echo "Updating images and rebuilding..."
	docker-compose pull
	docker-compose build --no-cache

# Quick development setup
quick-start: setup dev ## Quick start: setup environment and start development 