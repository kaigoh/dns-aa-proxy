FROM golang:1.23-alpine AS builder

WORKDIR /build

# Cache dependency downloads
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o dns-aa-proxy .

# ---

FROM alpine:3.23.4

RUN apk update && apk add --no-cache ca-certificates tzdata && adduser -D -H -s /sbin/nologin dnsProxy

COPY --from=builder /build/dns-aa-proxy /usr/local/bin/dns-aa-proxy

# dns-aa-proxy binds to port 53 which is privileged; allow the binary
# to do so without running as root.
RUN apk add --no-cache libcap \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/dns-aa-proxy \
    && apk del libcap

USER dnsProxy

EXPOSE 53/udp 53/tcp

ENTRYPOINT ["dns-aa-proxy"]
