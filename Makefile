.PHONY: dev-db migrate api worker web lab test test-backend test-frontend lint build

dev-db:        ## start local PostgreSQL and Redis (no Docker)
	./scripts/dev-db.sh
migrate:       ## apply database migrations
	cd backend && uv run alembic upgrade head
api:           ## run the API on :8000 (development settings)
	cd backend && CTEM_COOKIE_SECURE=false uv run uvicorn app.main:app --reload --port 8000
worker:        ## run a background worker and the scheduler
	cd backend && uv run python -m app.workers.runner
web:           ## run the frontend on :3000
	cd frontend && pnpm dev
lab:           ## start the local practice targets on :8808
	python3 scripts/lab.py
test: test-backend test-frontend
test-backend:
	cd backend && uv run pytest
test-frontend:
	cd frontend && pnpm test
lint:
	cd backend && uv run ruff check . && cd ../frontend && pnpm lint && pnpm typecheck
build:         ## production frontend build
	cd frontend && pnpm build
