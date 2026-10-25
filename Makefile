BINARY := fp
PKG := ./cmd/fp

.PHONY: all build test vet fmt check data docker clean

all: check build

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./... -race

vet:
	go vet ./...

fmt:
	gofmt -l .

# check runs everything CI runs, including the dataset validation test.
check: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt needs: $$(gofmt -l .)"; exit 1)
	go test ./... -race

# data validates that the embedded dataset parses and reverse-lookup works.
data:
	go test ./data/ -run Test -v

docker:
	docker build -t fpkit:local .

clean:
	rm -f $(BINARY)
	rm -rf dist
