SHELL := /bin/bash
DEFAULT_GOAL := help


.PHONY: help
help: ## Show this help
	@sed -e '/__hidethis__/d; /##/!d; s/:.\+## /\t/g' $(MAKEFILE_LIST)

.PHONY: up
up: ## Start project
	@cd local-env && if [ ! -f .env ]; then cp .env.example .env; echo "No .env file found. New created. Please try again"; exit 1 ; fi
	@cd local-env && docker-compose up -d
	@sleep 3
	@$(MAKE) seed

.PHONY: down
down: ## Stop project and cleanup with volumes
	@cd local-env && docker-compose down -v
	@find ./ -name '*.json' -delete

.PHONY: seed
seed: ## Seed local env
	@cd local-env && python seed.py
	@$(MAKE) kv-backup

.PHONY: kv-backup
kv-backup: ## Backup KV
	@cd local-env && consul kv export -http-addr=http://localhost:8500 vault > vault.local.json

.PHONY: analyze-local
analyze-local: ## Analyze local env backup
	@python vault_backup_analyzer.py local-env/vault.local.json localhost:9091 env=local,group=vault http://localhost:8200 local-env/creds.json
