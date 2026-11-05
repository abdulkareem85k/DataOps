.PHONY: up down test seed lint

up:
	@test -s .env || { cp .env.example .env; echo "Created .env from .env.example; generate ZAP_API_KEY and RUNNER_TOKEN, then run make up again."; exit 1; }
	@grep -Eq '^ZAP_API_KEY=.+$$' .env || { echo "Set ZAP_API_KEY in .env (for example: openssl rand -hex 32)."; exit 1; }
	@grep -Eq '^RUNNER_TOKEN=.+$$' .env || { echo "Set RUNNER_TOKEN in .env (for example: openssl rand -hex 32)."; exit 1; }
	docker compose up --build -d

down:
	docker compose down

test:
	cd backend && uv run --project . pytest -q tests
	cd runner && uv run --project . pytest -q tests
	npm --prefix frontend run build
	uv run --project backend python scripts/validate_compose.py

seed:
	cd backend && DATA_DIR=../data DB_URL=sqlite:///../data/vapt.db uv run --project . python -m app.seed

lint:
	cd backend && uv run --project . ruff check app tests
	cd runner && uv run --project . ruff check app tests
	npm --prefix frontend run typecheck
