.PHONY: caddy

caddy:
	xcaddy build --with github.com/rjevski/caddy-cloudflare-origin-ca=.

# Build Docker image
docker:
	docker build -t caddy-cloudflare-origin-ca .

# Run local Caddy with the module
run: caddy
	./caddy run --config Caddyfile.example
