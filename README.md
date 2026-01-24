# JT REST API Cache Poisoning Fix

A WordPress plugin that prevents cache poisoning attacks and provides comprehensive REST API access controls to reduce attack surface exposure.

## Features

- **Cache Poisoning Protection** — Blocks HTTP method override attacks that can break REST API caching
- **REST API Access Controls** — Restrict public access to `/wp-json/` endpoint and sensitive routes
- **IP-Based Restrictions** — Whitelist IPs/CIDR ranges for REST API access
- **User Endpoint Protection** — Hide `/wp/v2/users` endpoints from unauthenticated requests
- **Namespace Blocking** — Block specific API namespaces from public access
- **Admin Settings Page** — Easy configuration via WordPress admin (Settings → REST API Security)

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

The plugin works immediately upon activation with secure defaults. For advanced configuration, go to **Settings → REST API Security** in the WordPress admin.

### Default Security Settings

Out of the box, the plugin enables:
- ✅ Cache poisoning protection (always active)
- ✅ Root endpoint (`/wp-json/`) restriction for unauthenticated users
- ✅ User endpoints (`/wp/v2/users`) hidden from unauthenticated requests

### Admin Settings

| Setting | Description | Default |
|---------|-------------|---------|
| **Restrict Root Endpoint** | Blocks public access to `/wp-json/` index, preventing API enumeration | Enabled |
| **Hide User Endpoints** | Removes `/wp/v2/users` routes for unauthenticated requests | Enabled |
| **Require Authentication** | Requires auth for all REST API requests (with exceptions) | Disabled |
| **Allowed Public Routes** | Routes that bypass authentication requirement | Posts, pages, categories, tags, oembed |
| **Blocked Namespaces** | Completely block specific API namespaces | Empty |
| **IP Whitelist** | Only allow REST API access from specific IPs/CIDRs | Disabled |
| **Disable Application Passwords** | Disable WordPress Application Passwords feature | Disabled |

### Logging

When `WP_DEBUG` is set to `true`, the plugin logs blocked override attempts to the WordPress debug log:

```
[JT Cache Poisoning Fix] Blocked method override attempt - Header: HTTP_X_HTTP_METHOD_OVERRIDE, Value: HEAD, IP: 192.168.1.1, URI: /wp-json/wp/v2/posts
```

## Verifying the Fix

### Cache Poisoning Protection

1. Clear your CDN/edge cache
2. Send a request with the override header:
   ```bash
   curl -H "X-HTTP-Method-Override: HEAD" "https://example.com/wp-json/wp/v2/posts"
   ```
3. You should receive a **400 Bad Request** with:
   ```json
   {"code":"method_override_not_allowed","message":"HTTP method override headers are not permitted on this endpoint.","data":{"status":400}}
   ```
4. Subsequent unauthenticated requests should return normal responses

### REST API Access Controls

1. Test root endpoint restriction (when enabled):
   ```bash
   curl "https://example.com/wp-json/"
   ```
   Should return **403 Forbidden** with `rest_index_disabled` error.

2. Test user endpoint hiding (when enabled):
   ```bash
   curl "https://example.com/wp-json/wp/v2/users"
   ```
   Should return **404 Not Found** (endpoint doesn't exist for unauthenticated users).

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
