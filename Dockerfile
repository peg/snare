# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25.10-alpine AS builder

WORKDIR /src

# Download dependencies first (layer cache)
COPY go.mod go.sum ./
RUN go mod download

# Build the binary (pure Go, no CGo needed for modernc.org/sqlite)
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=docker" \
    -o /snare ./cmd/snare

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.24

RUN apk add --no-cache ca-certificates wget && \
    mkdir -p /data && chmod 700 /data

COPY --from=builder /snare /usr/local/bin/snare

VOLUME ["/data"]
EXPOSE 8080 80 443

ENTRYPOINT ["snare"]
CMD ["serve", "--port", "8080", "--db", "/data/snare.db"]
