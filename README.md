# dns-aa-proxy

A tiny DNS proxy that sits in front of Technitium (or any DNS server) and only exposes **authoritative** responses to the outside world. Non-authoritative (recursive) queries from external clients are refused.

This lets you run a full-featured recursive + authoritative DNS server internally while presenting only an authoritative face on port 53.

## Architecture

```
                         ┌─────────────────────────────────┐
                         │          Technitium              │
   Mobile devices ──DoT──┤  :853  (full recursion)          │
   Mobile devices ──DoH──┤  :443  (full recursion)          │
                         │                                  │
                         │  :5353 (internal, full features)  │
                         └──────────┬───────────────────────┘
                                    │
                         ┌──────────┴───────────────────────┐
   Public queries ──:53──┤       dns-aa-proxy                │
                         │  AA flag set? → forward response  │
                         │  AA flag not set? → REFUSED       │
                         │  Cluster peer? → always forward   │
                         │  NOTIFY/AXFR? → always forward    │
                         └──────────────────────────────────┘
```

## Environment Variables

| Variable           | Default          | Description                                                                 |
|--------------------|------------------|-----------------------------------------------------------------------------|
| `LISTEN_ADDR`      | `:53`            | Address and port to listen on                                               |
| `UPSTREAM`         | `127.0.0.1:5353` | Technitium DNS address (host:port)                                          |
| `CLUSTER_PEERS`    | *(empty)*        | Comma-separated IPs or CIDRs that bypass the AA check (e.g. `10.0.0.1,10.0.0.0/24`) |
| `UPSTREAM_TIMEOUT` | `5s`             | Timeout for upstream DNS queries (Go duration format)                       |
| `LOG_LEVEL`        | `info`           | Logging level: `debug`, `info`, `warn`, `error`                            |

## Behaviour

1. **Receives a query** on port 53 (TCP or UDP).
2. **Forwards it** to the upstream Technitium instance.
3. **Inspects the response:**
   - If the **AA (Authoritative Answer) flag** is set → forward the response to the client.
   - If the query is **NOTIFY, AXFR, or IXFR** → always forward (cluster sync).
   - If the client IP is in **`CLUSTER_PEERS`** → always forward (full access).
   - Otherwise → respond with **REFUSED**.

This means you never need to maintain a list of zones. Add or remove zones in Technitium and the proxy automatically does the right thing based on the AA flag.

## Running

### Docker Compose

```bash
docker compose up -d
```

See `docker-compose.yml` for the full stack with Technitium.

### Standalone

```bash
go build -o dns-aa-proxy .
UPSTREAM=127.0.0.1:5353 CLUSTER_PEERS=10.0.0.2,10.0.0.3 ./dns-aa-proxy
```

## Technitium Configuration

1. Change Technitium's DNS listener to port **5353** (or whatever you set `UPSTREAM` to).
2. Keep DoT (:853) and DoH (:443) on their standard ports — these bypass the proxy entirely.
3. Configure cluster peers to sync via the internal port (5353), not through the proxy.
4. Point your NS records to the host running dns-aa-proxy on port 53.

## Testing

```bash
# Should get an authoritative answer for your zones
dig @localhost example.com A

# Should get REFUSED for recursive queries
dig @localhost google.com A

# Run the test suite
go test -v -race ./...
```
