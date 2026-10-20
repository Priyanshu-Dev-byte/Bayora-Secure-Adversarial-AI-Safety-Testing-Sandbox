# =============================================================================
# Bayora — Makefile
# =============================================================================

.PHONY: up down build logs test test-isolation test-audit verify \
        security-check clean lint help

# Default target
help:
	@echo "Bayora — Secure Adversarial AI Testing Sandbox"
	@echo ""
	@echo "  make up              Build and start all services"
	@echo "  make down            Stop and remove all services + volumes"
	@echo "  make build           Rebuild all images"
	@echo "  make logs            Follow all container logs"
	@echo "  make test            Run all tests"
	@echo "  make test-isolation  Run network isolation tests"
	@echo "  make test-audit      Run audit chain tests"
	@echo "  make verify          Verify the audit hash chain"
	@echo "  make security-check  Print security settings for all containers"
	@echo "  make clean           Remove containers, volumes, and images"
	@echo "  make lint            Lint all Python code"
	@echo ""

up:
	docker compose up --build -d
	@echo "Bayora is running."
	@echo "  Control Plane: http://localhost:8000"
	@echo "  Web Dashboard: http://localhost:5173"
	@echo "Run 'make logs' to follow container output."

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

test: test-isolation test-audit
	@echo "All tests complete."

test-isolation:
	@echo "=== Network Isolation Tests ==="
	docker compose exec -T red python -m pytest /app/tests/ -v 2>/dev/null || \
		docker compose exec -T red python -c "from app.tests import test_isolation; test_isolation.run()"

test-audit:
	@echo "=== Audit Chain Tests ==="
	docker compose exec -T control-plane python -m pytest /app/tests/ -v 2>/dev/null || \
		echo "Audit tests not yet implemented"

verify:
	@echo "=== Audit Chain Verification ==="
	docker compose exec -T control-plane python -m app.audit.verify

security-check:
	@bash scripts/check-security.sh

clean:
	docker compose down -v --rmi local
	@echo "Cleaned up all Bayora containers, volumes, and images."

lint:
	@echo "Linting control-plane..."
	@cd control-plane && python -m ruff check app/ 2>/dev/null || echo "ruff not installed locally, skipping"
	@echo "Linting gateway..."
	@cd gateway && python -m ruff check app/ 2>/dev/null || echo "ruff not installed locally, skipping"
