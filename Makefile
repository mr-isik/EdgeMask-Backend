.PHONY: run build test tidy \
       docker-up docker-down docker-prod docker-logs docker-clean docker-ps \
       migrate swagger

# ─── Go ──────────────────────────────────────────────────────
run:
	go run cmd/api/main.go

build:
	go build -o bin/api cmd/api/main.go

test:
	go test -v ./...

tidy:
	go mod tidy

# ─── Docker (Development) ───────────────────────────────────
docker-up: swagger
	docker compose up --build -d

# Keep docs/docs.go + docs/swagger.* in sync with code annotations.
swagger:
	go run github.com/swaggo/swag/cmd/swag@latest init -g cmd/api/main.go -o docs

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f api

docker-ps:
	docker compose ps

docker-clean:
	docker compose down -v --rmi local

# ─── Docker (Production) ────────────────────────────────────
docker-prod:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
