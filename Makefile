# RedFlag Antifraud — единая точка входа для разработки.  `make` без аргументов покажет справку.
.DEFAULT_GOAL := help
SHELL := /bin/bash

PY        ?= python3
STATICCHECK ?= $(shell command -v staticcheck 2>/dev/null || echo $(HOME)/go/bin/staticcheck)
URL       ?= http://127.0.0.1:8000
NUMPLAN   ?= $(NUMPLAN_DIR)
DATA      ?=
BIN       := bin
ML        := services/ml

.PHONY: help
help: ## Показать эту справку
	@awk 'BEGIN{FS=":.*##"; printf "\nЦели:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo

## ---- Сборка ------------------------------------------------------------------------------------------
.PHONY: build
build: ## Собрать все бинарники в ./bin
	@mkdir -p $(BIN)
	go build -trimpath -ldflags="-s -w" -o $(BIN)/ ./cmd/...

.PHONY: run
run: ## Запустить ядро локально (NUMPLAN_DIR, ML_URL и др. — из окружения)
	go run ./cmd/decision-api

.PHONY: docker
docker: ## Собрать образы ядра и ML-сервиса
	docker build -t redflag-antifraud-app:local .
	docker build -t redflag-ml:local $(ML)

## ---- Качество ---------------------------------------------------------------------------------------
.PHONY: fmt
fmt: ## Отформатировать Go и Python
	gofmt -w cmd internal
	cd $(ML) && $(PY) -m ruff format .

.PHONY: lint
lint: ## Проверки стиля и статический анализ (Go и Python)
	@test -z "$$(gofmt -l cmd internal)" || (echo "gofmt: не отформатированы:"; gofmt -l cmd internal; exit 1)
	go vet ./...
	$(STATICCHECK) ./...
	cd $(ML) && $(PY) -m ruff check . && $(PY) -m ruff format --check .

.PHONY: test
test: ## Тесты Go (с детектором гонок) и Python
	go test -race ./...
	cd $(ML) && $(PY) -m pytest -q

.PHONY: cover
cover: ## Покрытие тестами Go по пакетам
	go test -cover ./... | grep -v "no test files"

.PHONY: bench
bench: ## Бенчмарки горячего пути
	go test -run xxx -bench . -benchmem ./internal/telecom/... ./internal/detection/... ./internal/decision/...

.PHONY: check
check: lint test ## Полная проверка перед коммитом (lint + test)

## ---- Данные и модели ------------------------------------------------------------------------------
.PHONY: retrain
retrain: ## Переобучить обе стадии: make retrain NUMPLAN=/путь [DATA=файл.csv|jsonl]
	@test -n "$(NUMPLAN)" || (echo "укажите NUMPLAN=/путь/к/справочнику"; exit 1)
	PYTHON=$(PY) scripts/retrain.sh $(NUMPLAN) $(DATA)

.PHONY: demo
demo: ## Демо-сценарии и смоук-тест сервиса: make demo URL=http://host:8000
	$(PY) scripts/demo.py --url $(URL) --fan

.PHONY: clean
clean: ## Удалить артефакты сборки
	rm -rf $(BIN)
