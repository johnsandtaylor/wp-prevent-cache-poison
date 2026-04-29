# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-04-28

### Added
- `X-Original-URL` and `X-Rewrite-URL` added to the always-reject header set. These IIS-style URL-rewrite headers are honored by some PHP/WordPress configurations and can override `REQUEST_URI` server-side, enabling cache poisoning where the cache keys on the original URL but WordPress responds based on the rewritten one.
- Silent-strip pass for host-poisoning headers: `X-Forwarded-Host`, `X-Host`, `X-Original-Host`, `X-Forwarded-Server`. Stripped from `$_SERVER` on every request so WordPress falls back to `HTTP_HOST` (set correctly by the origin web server) when generating absolute URLs in canonical links, `og:url`, password-reset emails, RSS feeds, and similar surfaces. No 400 — these headers are routinely inserted by upstream proxies on legitimate traffic and rejecting would break it.
- `STRIP_HEADERS` constant introduced to distinguish the silent-strip set from the always-reject set.
- `REJECT_HEADERS` constant added; `OVERRIDE_HEADERS` retained as a backwards-compatible alias.
- `Vary` header on rejected requests and on filtered REST API responses now includes the URL-rewrite headers in addition to the method-override headers.

### Changed
- Rejection error code generalized from `method_override_not_allowed` to `request_header_not_allowed` since the reject set now covers both method-override and URL-rewrite vectors.
- Late-bound `strip_method_override_headers()` (init priority 1 fallback) now also strips the new reject and silent-strip header sets.

### Security
- Addresses follow-up Bugcrowd researcher concern (Comcast PSIRT, 04-02-26) that the v1.4.0 fix was too narrow: "cache poisoning is not limited to this header. Other unkeyed inputs (e.g., X-Forwarded-Host, X-Host, or query variations) may still influence cached responses." This release expands application-layer coverage to the broader header class. Cache-key strategy and edge-layer treatment of unkeyed inputs remain a Pagely-side concern (see `pagely-support-ticket.md`).

## [1.4.0] - 2026-03-26

### Changed
- **SECURITY**: Override header rejection now applies to ALL incoming requests, not just REST API paths (`/wp-json`, `/wp/v2`). Override headers have no legitimate use case on any WordPress endpoint, and path-restricted checking left other cached endpoints vulnerable.
- Header stripping now happens BEFORE rejection logic as a CDN failsafe — even if rejection fails for any reason, WordPress never sees the override header.
- Refactored `early_reject_override_requests()` to strip-then-detect-then-reject flow for defense in depth.

### Fixed
- Added `class_exists` guards for both `JT_REST_Cache_Poisoning_Fix` and `JT_REST_Cache_Poisoning_Fix_Updater` to prevent fatal "Cannot declare class" errors when multiple copies of the plugin are installed (e.g., manual update extracts to a versioned folder alongside the original).

### Security
- Addresses Bugcrowd-reported cache poisoning vulnerability on talentbrand.comcast.com where `X-HTTP-Method-Override: HEAD` on `/wp-json/?cb=<cachebuster>` returned empty cached responses.
- Fixes edge case where CDN configurations that ignore `Cache-Control: no-store` on 400 responses could still cache poisoned entries — headers are now stripped unconditionally so a normal 200 is never generated from an overridden method.
- Eliminates reliance on URI pattern matching as a security boundary, which is unreliable when CDNs normalize or rewrite request paths before they reach PHP.

## [1.3.3] - 2026-01-23

### Fixed
- Fixed GitHub updater `after_install` method to properly rename extracted folder from GitHub's zipball format (e.g., `user-repo-hash`) to the expected plugin folder name, preventing duplicate plugin conflicts

## [1.3.2] - 2026-01-23

### Added
- "Check for Updates" button on the admin settings page to manually trigger update checks from GitHub
- "View Releases on GitHub" button for quick access to release notes
- Success notification after triggering an update check

## [1.3.1] - 2026-01-23

### Fixed
- Fixed `explode()` type error when sanitizing settings that were already stored as arrays

## [1.3.0] - 2026-01-23

### Added
- **REST API Access Controls** to address pentest finding about `/wp-json/` endpoint exposure
- Admin settings page under **Settings → REST API Security** for configuring all security options
- Root endpoint restriction: Blocks public access to `/wp-json/` to prevent API enumeration
- User endpoint hiding: Removes `/wp/v2/users` routes for unauthenticated requests (prevents username enumeration)
- Authentication requirement option: Require auth for all REST API requests with configurable exceptions
- IP whitelist feature: Restrict REST API access to specific IP addresses or CIDR ranges
- Namespace blocking: Completely block specific API namespaces from public access
- Allowed public routes: Configure which routes remain accessible when authentication is required
- Application Passwords disable option
- Security status dashboard showing active protections
- `filter_rest_endpoints()` method to hide sensitive endpoints from discovery
- `filter_rest_index()` method to strip metadata from root endpoint response
- `check_rest_api_access()` method for comprehensive access control
- CIDR notation support for IP whitelisting

### Security
- Addresses pentest finding: "The endpoint /wp-json/ remains publicly accessible without authentication"
- Reduces attack surface by hiding available API endpoints, namespaces, and routes from unauthenticated users
- Default settings now restrict root endpoint and hide user endpoints out of the box

## [1.2.0] - 2026-01-20

### Changed
- **BREAKING**: Requests with method override headers now receive 400 Bad Request instead of being silently processed
- Early rejection strategy replaces header stripping to prevent upstream cache poisoning
- Aggressive no-cache headers added to rejected requests to prevent Pagely ARES caching

### Added
- `early_reject_override_requests()` static method for immediate request rejection
- Pagely-specific cache control headers (`X-Accel-Expires`, `Surrogate-Control`)
- JSON error response body for rejected requests with `method_override_not_allowed` code
- `Expires` header set to epoch for maximum cache prevention compatibility
- **GitHub auto-updater**: Plugin now checks for updates from GitHub releases automatically
- "View releases on GitHub" link added to plugin row meta on Plugins page
- Plugin details popup shows release notes from GitHub

### Security
- Fixes incomplete cache poisoning mitigation where stripped headers still resulted in cacheable 200 responses
- Addresses CVE-related finding where Pagely ARES cached responses without keying on `X-Http-Method-Override` header
- 400 responses with no-store prevent poisoned entries from entering the cache layer

### Deprecated
- `early_strip_headers()` method (now calls `early_reject_override_requests()` for backwards compatibility)

## [1.1.0] - 2025-12-11

### Added
- Early header stripping on plugin load (before `plugins_loaded` hook) to prevent race conditions
- Protection against `_method` parameter-based method override attacks (used by Laravel, Rails, etc.)

### Changed
- IP detection now prioritizes `REMOTE_ADDR` over proxy headers for more reliable logging
- Added security documentation noting that logged IPs from proxy headers may be spoofed

### Security
- Hardened against timing attacks where other plugins might read headers before our `init` hook

## [1.0.0] - 2025-12-11

### Added
- Initial release
- Strip `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override` headers from REST API requests
- Add `Vary` headers to REST API responses for cache differentiation
- Add `Cache-Control: no-cache` headers for unauthenticated REST API requests
- Security logging when `WP_DEBUG` is enabled
- Support for common proxy headers when logging client IPs (Cloudflare, X-Forwarded-For, X-Real-IP)

### Security
- Mitigates cache poisoning vulnerability (CVE pending) where attackers could break REST API for unauthenticated users
