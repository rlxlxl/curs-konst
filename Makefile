.PHONY: help build up down restart logs clean rebuild shell-backend shell-db test

# Переменные
COMPOSE = docker-compose
COMPOSE_FILE = docker-compose.yml

# Цвета для вывода
GREEN = \033[0;32m
YELLOW = \033[1;33m
NC = \033[0m # No Color

help: ## Показать справку по командам
	@echo "$(GREEN)Доступные команды:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'

build: ## Собрать Docker образы
	@echo "$(GREEN)Сборка Docker образов...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) build

up: ## Запустить все контейнеры
	@echo "$(GREEN)Запуск контейнеров...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo "$(GREEN)✓ Сервисы запущены!$(NC)"
	@echo "$(YELLOW)Фронтенд: http://localhost:8080$(NC)"
	@echo "$(YELLOW)Backend API: http://localhost:8081$(NC)"

down: ## Остановить все контейнеры
	@echo "$(GREEN)Остановка контейнеров...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) down

restart: ## Перезапустить все контейнеры
	@echo "$(GREEN)Перезапуск контейнеров...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) restart

stop: ## Остановить контейнеры (без удаления)
	@echo "$(GREEN)Остановка контейнеров...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) stop

start: ## Запустить остановленные контейнеры
	@echo "$(GREEN)Запуск контейнеров...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) start

logs: ## Показать логи всех сервисов
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

logs-backend: ## Показать логи backend
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f backend

logs-frontend: ## Показать логи frontend
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f frontend

logs-db: ## Показать логи базы данных
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f database

clean: ## Остановить и удалить контейнеры, volumes и сети (используйте clean-force для удаления без подтверждения)
	@echo "$(YELLOW)ВНИМАНИЕ: Это удалит все данные базы данных!$(NC)"
	@echo "$(YELLOW)Используйте 'make clean-force' для удаления без подтверждения$(NC)"

clean-force: ## Остановить и удалить контейнеры, volumes и сети без подтверждения
	@echo "$(YELLOW)Удаление всех контейнеров, volumes и сетей...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) down -v
	@echo "$(GREEN)✓ Все контейнеры, volumes и сети удалены$(NC)"

rebuild: ## Пересобрать и перезапустить проект
	@echo "$(GREEN)Пересборка проекта...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) down
	$(COMPOSE) -f $(COMPOSE_FILE) build --no-cache
	$(COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo "$(GREEN)✓ Проект пересобран и запущен!$(NC)"

rebuild-backend: ## Пересобрать только backend
	@echo "$(GREEN)Пересборка backend...$(NC)"
	$(COMPOSE) -f $(COMPOSE_FILE) build --no-cache backend
	$(COMPOSE) -f $(COMPOSE_FILE) up -d backend

shell-backend: ## Открыть shell в контейнере backend
	$(COMPOSE) -f $(COMPOSE_FILE) exec backend /bin/bash

shell-db: ## Открыть psql в контейнере базы данных
	$(COMPOSE) -f $(COMPOSE_FILE) exec database psql -U postgres -d infosec_db

status: ## Показать статус контейнеров
	$(COMPOSE) -f $(COMPOSE_FILE) ps

test: ## Проверить работу API
	@echo "$(GREEN)Проверка API endpoints...$(NC)"
	@echo "$(YELLOW)GET /api/sections:$(NC)"
	@curl -s http://localhost:8080/api/sections | python3 -m json.tool | head -10 || echo "Ошибка подключения"
	@echo ""
	@echo "$(YELLOW)GET /api/content?section_id=1:$(NC)"
	@curl -s "http://localhost:8080/api/content?section_id=1" | python3 -m json.tool | head -10 || echo "Ошибка подключения"

init: build up ## Первоначальная инициализация проекта
	@echo "$(GREEN)Ожидание запуска базы данных...$(NC)"
	@sleep 5
	@echo "$(GREEN)✓ Проект инициализирован!$(NC)"
	@echo "$(YELLOW)Фронтенд: http://localhost:8080$(NC)"
	@echo "$(YELLOW)Администратор: admin / admin123$(NC)"

.DEFAULT_GOAL := help

