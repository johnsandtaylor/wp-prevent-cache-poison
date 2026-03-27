# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-03-26

### Changed
- **SECURITY**: Override header rejection now applies to ALL incoming requests, not just REST API paths (`/wp-json`, `/wp/v2`). Override headers have no legitimate use case on any WordPress endpoint, and path-restricted checking left other cached endpoints vulnerable.
- Header stripping now happens BEFORE rejection logic as a CDN failsafe — even if rejection fails for any reason, WordPress never sees the override header.
- Refactored `early_reject_override_requests()` to strip-then-detect-then-reject flow for defense in depth.

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
