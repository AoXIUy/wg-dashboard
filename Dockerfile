# Multi-stage build for WireGuard Pro Dashboard (Single Binary)
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o wg-dashboard .

# Final minimal runtime container
FROM alpine:3.20

RUN apk add --no-cache wireguard-tools iproute2 ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/wg-dashboard /app/wg-dashboard

# Default sandbox data volume
VOLUME ["/etc/wireguard", "/app/.sandbox_data"]

EXPOSE 18080

ENTRYPOINT ["/app/wg-dashboard"]
CMD ["-port", ":18080"]
