VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test cover lint lab lab-restart lab-stop demo e2e

build:
	go build -ldflags "$(LDFLAGS)" -o dist/authdiff ./cmd/authdiff

test:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./internal/...
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

# Start the deliberately vulnerable lab on 127.0.0.1:8000 and wait until healthy.
lab:
	docker compose up -d --build --wait vuln-lab

# The lab is stateful (in-memory DB seeded on start); destructive scans mutate
# it. Recreating the container restores the seed data.
lab-restart:
	docker compose up -d --build --force-recreate --wait vuln-lab

lab-stop:
	docker compose down

# Scan the lab with the example config. Exit code 1 (findings above failOn)
# is expected here; 2 (error) still fails the target.
demo: build lab
	set -a; . ./examples/vuln-lab.env; set +a; \
	./dist/authdiff scan -c examples/authdiff.yaml; s=$$?; [ $$s -le 1 ]

# End-to-end test: always against a freshly recreated lab.
e2e: lab-restart
	go test -tags e2e -count=1 -v ./test/e2e/...
