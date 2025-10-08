# Caddy support for Cloudflare Origin CA

This module implements support for automatically obtaining certificates for Cloudflare's [Origin CA](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/).

If your Caddy is only intended to be reachable from behind Cloudflare, using their CA allows you to avoid involving an additional third-party such as a publicly-trusted CA. More info in their [introductory blog post](https://blog.cloudflare.com/cloudflare-ca-encryption-origin/).

## Known issues

Renewal at runtime currently does not work due to Cloudflare overriding the CommonName in the returned certificate, see upstream discussion: https://github.com/caddyserver/certmagic/issues/356. The renewed cert is correctly written to storage, but will not be loaded until the next server restart (if you are already affected by the problem, simply restarting the server should fix it).

As a workaround, set the requested validity to the 15-year max. This is the default, so simply omit the `validity` config key.

## Installation

Take the Dockerfile in this repo, tweak it if necessary, build it and push it to your private container registry.

If you're already building your own Caddy image, just add the `--with github.com/rjevski/caddy-cloudflare-origin-ca` option to your existing `xcaddy` invocation.

## Usage

Go to your Cloudflare user profile and obtain an Origin CA key. This is an API key specifically scoped to Origin CA certificate operations, to adhere to the principle of least privilege.

### Single domain

In your Caddyfile:

```
https://example.com {
	tls {
		issuer cloudflare_origin_ca {
			service_key "<YOUR API KEY HERE>"
			# optional - do not set it low as renewal does not work, see "known issues"
			# validity 7d
		}
	}
	respond "Hello world!"
}
```

This will obtain and automatically renew a certificate for `example.com`. You need to make sure this domain is configured as a "proxied" domain in your Cloudflare DNS zone.

Note: it's not recommended to hardcode API keys in your Caddyfile directly, instead pass it as an environment variable and use [interpolation/templating](https://caddyserver.com/docs/caddyfile/concepts#environment-variables) to reference it in your Caddyfile, like so:

```
service_key {$CF_ORIGIN_CA_SERVICE_KEY}
```

### "Custom Hostnames"

[Cloudflare for SaaS](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/) allows third-party domains to be CNAME'd to your Cloudflare account and Cloudflare will manage their public-facing certificates and pass on the traffic to you. However, this has some pitfalls:

* Cloudflare will pass the original (third-party) domain in the SNI
* However, you are unable to obtain a certificate via this Origin CA for third-party domains (you will get error 1010 "Failed to validate requested hostname example.com: This zone is either not part of your account, or you do not have access to it. Please contact support if using a multi-user organization.").
* It turns out despite the SNI, Cloudflare [will accept the certificate corresponding to your "fallback hostname"](https://community.cloudflare.com/t/unable-to-obtain-origin-ca-certificates-for-custom-hostnames/841881/2).

Therefore, we must:

* set the [`fallback_sni`](https://caddyserver.com/docs/caddyfile/options#fallback-sni) global directive to your "fallback domain" as configured in Cloudflare's SSL/TLS settings
* define this issuer module at the top-level to replace all other issuers (maybe not necessary? not tested)
* open an `https://` site block starting with your fallback domain
* on the same site block, add a catch-all `https://` matcher to catch all the other domains (since CF presents them in the SNI)
* if using ["authenticated origin pulls"](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) (mutual TLS), set the [`strict_sni_host insecure_off`](https://caddyserver.com/docs/caddyfile/options#strict-sni-host) server directive, *and make sure to not do access control based on SNI* (for authenticated origin pulls, you should be requiring mutual TLS unconditionally, so this is fine)

Example:

```
{
    fallback_sni example.com
    servers {
        strict_sni_host insecure_off
    }
    
    cert_issuer cloudflare_origin_ca {
		service_key "<YOUR API KEY HERE>"
		# optional
		validity 7d
	}
}

https://example.com, https:// {
    respond "Hello world! SNI: {http.request.tls.server_name}, HTTP Host: {http.request.host}"
}
```

## Credits

This work has been graciously funded by [JobMaps](https://jobmaps.ch).

## License

Apache 2.0. See `LICENSE` for the full license text.
