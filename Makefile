VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test cover lint lab demo e2e

build:
	go build -ldflags "$(LDFLAGS)" -o dist/authdiff ./cmd/authdiff

test:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./internal/...
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

lab:
	docker compose up -d --build vuln-lab

demo: build lab
	./dist/authdiff scan --config examples/authdiff.demo.yaml

e2e:
	go test -tags e2e ./test/e2e/...
