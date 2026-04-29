=== JT REST API Cache Poisoning Fix ===
Contributors: johnsandtaylor
Tags: security, rest-api, cache, vulnerability
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Prevents cache poisoning attacks via attacker-controlled override and host headers, and restricts REST API endpoint exposure.

== Description ==

This plugin mitigates a class of cache poisoning vulnerabilities where attackers can send special HTTP headers to cause empty, altered, or attacker-influenced responses to be cached by upstream caching layers (like Pagely ARES), breaking the site for legitimate users or feeding poisoned content (canonical URLs, password-reset emails, RSS feeds) to other visitors.

**What it does:**

* **Rejects requests** with method-override or URL-rewrite headers immediately with 400 Bad Request
* **Silently strips** host-poisoning headers (X-Forwarded-Host etc.) so WordPress falls back to the real Host header
* Returns aggressive no-cache headers to prevent upstream cache poisoning of error responses
* Blocks `_method` parameter-based method overrides (used by some frameworks)
* Adds Vary headers to REST API responses for cache key differentiation
* Includes Pagely ARES-specific headers (`X-Accel-Expires`, `Surrogate-Control`)
* Logs blocked attempts when WP_DEBUG is enabled
* **Auto-updates** from GitHub releases (no WordPress.org dependency)

**Headers rejected (HTTP 400):**

* X-HTTP-Method-Override
* X-HTTP-Method
* X-Method-Override
* X-Original-URL
* X-Rewrite-URL

**Headers stripped silently:**

* X-Forwarded-Host
* X-Host
* X-Original-Host
* X-Forwarded-Server

**Parameters blocked:**

* _method (GET/POST)

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`
2. Activate the plugin through the Plugins menu
3. No configuration required

== Changelog ==

= 1.5.0 =
* **SECURITY**: Added `X-Original-URL` and `X-Rewrite-URL` to the always-reject set (IIS-style URL-rewrite headers that can override REQUEST_URI server-side)
* **SECURITY**: Added silent-strip pass for host-poisoning headers (`X-Forwarded-Host`, `X-Host`, `X-Original-Host`, `X-Forwarded-Server`) so attacker-controlled host values cannot influence absolute URL generation
* Generalized rejection error code to `request_header_not_allowed`
* Vary header now includes URL-rewrite header family in addition to method-override
* Addresses Bugcrowd researcher follow-up that the original fix was too narrow

= 1.4.0 =
* **SECURITY**: Override header rejection now applies to ALL requests, not just REST API paths
* Headers stripped BEFORE rejection as CDN failsafe — WordPress never sees the override header
* Addresses Bugcrowd-reported cache poisoning where CDNs ignored no-cache on 400 responses
* Eliminates path-based filtering as a security boundary (unreliable with CDN path normalization)

= 1.3.3 =
* Fixed GitHub updater folder rename on update installation

= 1.3.2 =
* Added manual "Check for Updates" button on admin settings page

= 1.3.1 =
* Fixed explode() type error when sanitizing array settings

= 1.3.0 =
* Added REST API access controls (root endpoint, user endpoints, auth requirements, IP whitelist)
* Admin settings page under Settings > REST API Security
* Namespace blocking and allowed public routes configuration

= 1.2.0 =
* **SECURITY**: Complete fix for cache poisoning on Pagely ARES
* Requests with override headers now rejected with 400 (previously stripped and processed)
* Added aggressive no-cache headers to prevent poisoned cache entries
* Added Pagely-specific headers (X-Accel-Expires, Surrogate-Control)
* Returns JSON error response for rejected requests
* Added automatic updates from GitHub releases

= 1.1.0 =
* Early header stripping on plugin load (before plugins_loaded hook)
* Added protection against _method parameter-based method override attacks
* Improved IP detection reliability for logging
* Added security documentation for IP spoofing considerations

= 1.0.0 =
* Initial release
* Strips method override headers from REST API requests
* Adds Vary and Cache-Control headers for defense in depth
* Security logging when WP_DEBUG enabled
