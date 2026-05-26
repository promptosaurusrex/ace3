.PHONY: db-revision db-upgrade db-downgrade db-seed db-check \
        cache-db-revision cache-db-upgrade cache-db-downgrade cache-db-check

db-revision:
	docker compose exec dev /venv/bin/alembic revision --autogenerate -m "$(MESSAGE)"

db-upgrade:
	docker compose exec dev /venv/bin/alembic upgrade head

db-downgrade:
	docker compose exec dev /venv/bin/alembic downgrade -1

db-seed:
	docker compose exec dev /venv/bin/python bin/seed_database.py

db-check:
	docker compose exec -e DATABASE_NAME=ace-unittest-2 dev /venv/bin/python bin/check_model_drift.py

cache-db-revision:
	docker compose exec dev /venv/bin/alembic -c alembic_analysis_cache.ini revision --autogenerate -m "$(MESSAGE)"

cache-db-upgrade:
	docker compose exec dev /venv/bin/alembic -c alembic_analysis_cache.ini upgrade head

cache-db-downgrade:
	docker compose exec dev /venv/bin/alembic -c alembic_analysis_cache.ini downgrade -1

cache-db-check:
	docker compose exec -e CACHE_DATABASE_NAME=analysis-result-cache-unittest dev /venv/bin/python bin/check_model_drift.py --cache
