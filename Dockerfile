FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy dependency files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /airlock ./proxy/

# --- Runtime stage ---
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /airlock /app/airlock

EXPOSE 8080

ENTRYPOINT ["/app/airlock"]
