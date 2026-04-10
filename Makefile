.PHONY: backend-install frontend-install pg-up pg-down backend-test frontend-test phase1-verify

VENV_PYTHON := ./.venv/bin/python
TEST_DATABASE_URL ?= postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev

backend-install:
	timeout 60s bash scripts/bootstrap_backend_env.sh

frontend-install:
	timeout 60s npm --prefix frontend install

pg-up:
	docker compose -f infra/docker-compose.dev.yml up -d postgres
	until docker compose -f infra/docker-compose.dev.yml exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done

pg-down:
	docker compose -f infra/docker-compose.dev.yml down -v

backend-test:
	TEST_DATABASE_URL=$(TEST_DATABASE_URL) timeout 60s $(VENV_PYTHON) -m pytest backend/tests -q

frontend-test:
	timeout 60s npm --prefix frontend test -- --run

phase1-verify: pg-up
	TEST_DATABASE_URL=$(TEST_DATABASE_URL) timeout 60s $(VENV_PYTHON) -m pytest backend/tests -q
	timeout 60s npm --prefix frontend test -- --run
	timeout 60s npm --prefix frontend run build
