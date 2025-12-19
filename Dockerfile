ARG BUILDER_IMAGE_VARIANT=2-builder
ARG RUNTIME_IMAGE_VARIANT=2

FROM caddy:${BUILDER_IMAGE_VARIANT} AS builder

COPY go.mod go.sum src/

COPY *.go src/

RUN xcaddy build \
    --with github.com/rjevski/caddy-cloudflare-origin-ca=./src

# Final stage
ARG RUNTIME_IMAGE_VARIANT
FROM caddy:${RUNTIME_IMAGE_VARIANT}

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
