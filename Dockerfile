FROM caddy:2-builder AS builder

COPY go.mod go.sum src/

COPY *.go src/

RUN xcaddy build \
    --with github.com/rjevski/caddy-cloudflare-origin-ca=src/

# Final stage
FROM caddy:2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
