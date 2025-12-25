# ---------- build stage ----------
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o scanner ./cmd/scanner
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o webui ./cmd/webui


# ---------- runtime stage ----------
FROM alpine:3.19

# masscan + nmap + iproute2
RUN apk add --no-cache \
    masscan \
    nmap \
    iproute2 \
    ca-certificates

WORKDIR /app

COPY --from=builder /app/scanner /app/scanner
COPY --from=builder /app/webui /app/webui
COPY config.example.yaml /app/config.yaml

# директория под БД
RUN mkdir -p /data

EXPOSE 8088

# по умолчанию — Web UI
ENTRYPOINT ["/app/webui"]
CMD ["-config", "/app/config.yaml"]
