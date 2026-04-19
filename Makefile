.PHONY: all build test clean

BINARY_NAME=bgpwatch

all: build

build:
	go build -o $(BINARY_NAME) .

test:
	go test ./...

clean:
	go clean
	rm -f $(BINARY_NAME)
