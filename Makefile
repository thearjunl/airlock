.PHONY: build run test clean

# Build the AirLock proxy binary
build:
	go build -o bin/airlock ./proxy/

# Run the proxy server
run:
	go run ./proxy/

# Run all tests
test:
	go test -v ./...

# Run tests with coverage
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html

# Lint the code (requires golangci-lint)
lint:
	golangci-lint run ./...

# Format the code
fmt:
	gofmt -w .
