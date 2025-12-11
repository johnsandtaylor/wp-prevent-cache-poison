# JT REST API Cache Poisoning Fix

A WordPress plugin that prevents cache poisoning attacks via HTTP method override headers on REST API endpoints.

## The Vulnerability

Attackers can poison CDN/edge caches by sending requests with headers like `X-HTTP-Method-Override: HEAD` to REST API endpoints. WordPress respects these headers, treating a GET request as HEAD and returning an empty response body. If this empty response gets cached, the REST API becomes broken for all unauthenticated users until the cache expires.

**Impact:**
- Public REST API endpoints return empty responses
- Breaks frontend apps, headless WordPress clients, and third-party integrations
- Causes denial of service until cache clears

**Affected endpoints:** Any `/wp-json/*` endpoint accessible to unauthenticated users.

## How This Plugin Fixes It

1. **Strips override headers** — Removes `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override` from requests before WordPress processes them.

2. **Adds `Vary` headers** — Instructs caches to store separate versions based on override headers (defense in depth).

3. **Cache control for anonymous requests** — Adds `no-cache` headers to REST API responses for unauthenticated users.

4. **Security logging** — Logs blocked attempts when `WP_DEBUG` is enabled.

## Installation

### Manual Installation
1. Download the latest release
2. Upload `jt-rest-api-cache-poisoning-fix.php` to `/wp-content/plugins/`
3. Activate the plugin through the WordPress admin

### Via Composer
```bash
composer require johnsandtaylor/jt-rest-api-cache-poisoning-fix
```

## Requirements

- WordPress 5.0 or higher
- PHP 7.4 or higher

## Configuration

No configuration required. The plugin works immediately upon activation.

### Logging

When `WP_DEBUG` is set to `true`, the plugin logs blocked override attempts to the WordPress debug log:

```
[JT Cache Poisoning Fix] Blocked method override attempt - Header: HTTP_X_HTTP_METHOD_OVERRIDE, Value: HEAD, IP: 192.168.1.1, URI: /wp-json/wp/v2/posts
```

## Verifying the Fix

1. Clear your CDN/edge cache
2. Send a request with the override header:
   ```bash
   curl -H "X-HTTP-Method-Override: HEAD" "https://example.com/wp-json/wp/v2/posts"
   ```
3. The response should contain the full JSON body (not empty)
4. Subsequent unauthenticated requests should also return full responses

## Compatibility

This plugin is compatible with:
- WordPress Multisite
- Popular caching plugins (WP Super Cache, W3 Total Cache, etc.)
- CDN providers (Cloudflare, Fastly, Akamai, etc.)
- REST API authentication plugins

### Breaking Change Warning

If any legitimate application relies on `X-HTTP-Method-Override` headers to access your REST API (rare, but some legacy mobile clients used this), those requests will no longer work as expected. The override will be stripped and the actual HTTP method will be used instead.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

GPL v2 or later. See [LICENSE](LICENSE) for details.

## Credits

Developed by [Johns & Taylor](https://johnsandtaylor.com) in response to a security researcher's report.

## Support

For issues and feature requests, please use the [GitHub issue tracker](https://github.com/johnsandtaylor/jt-rest-api-cache-poisoning-fix/issues).
