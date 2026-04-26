.PHONY: all build test clean proto integration

BINARY_NAME=bgpwatch

all: build

proto:
	PATH=/zfs0/zcode/bin:$$PATH protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative proto/bgpwatch.proto

build:
	go build -o $(BINARY_NAME) ./cmd/bgpwatch

test:
	go test ./...

clean:
	go clean
	rm -f $(BINARY_NAME)

integration:
	go test -tags integration -v -count=1 -timeout 120s ./integration/

fuzz:
	go test -fuzz=FuzzDecodePathAttributes -fuzztime 20s ./internal/bgp
	go test -fuzz=FuzzDecodeIPv4Withdraws -fuzztime 20s ./internal/bgp
	go test -fuzz=FuzzDecodeIPv4NLRI -fuzztime 20s ./internal/bgp
	go test -fuzz=FuzzDecodeIPv6NLRI -fuzztime 20s ./internal/bgp
	go test -fuzz=FuzzDecodeMPReachNLRI -fuzztime 20s ./internal/bgp
	go test -fuzz=FuzzDecodeMPUnreachNLRI -fuzztime 20s ./internal/bgp
	go test -fuzz=FuzzDecodeOptionalParameters -fuzztime 20s ./internal/bgp
