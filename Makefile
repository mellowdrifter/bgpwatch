.PHONY: all build test clean proto

BINARY_NAME=bgpwatch

all: build

proto:
	PATH=/zfs0/zcode/bin:$$PATH protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative proto/bgpwatch.proto

build:
	go build -o $(BINARY_NAME) .

test:
	go test ./...

clean:
	go clean
	rm -f $(BINARY_NAME)
