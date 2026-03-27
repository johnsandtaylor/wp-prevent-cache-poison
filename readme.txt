=== JT REST API Cache Poisoning Fix ===
Contributors: johnsandtaylor
Tags: security, rest-api, cache, vulnerability
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Prevents cache poisoning attacks via X-HTTP-Method-Override header on REST API endpoints.

== Description ==

This plugin mitigates a cache poisoning vulnerability where attackers can send `X-HTTP-Method-Override: HEAD` headers to cause empty or malformed responses to be cached by upstream caching layers (like Pagely ARES), breaking the REST API for legitimate users.

**What it does:**

* **Rejects requests** with method override headers immediately with 400 Bad Request
* Returns aggressive no-cache headers to prevent upstream cache poisoning
* Blocks `_method` parameter-based overrides (used by some frameworks)
* Adds Vary headers to REST API responses for cache key differentiation
* Includes Pagely ARES-specific headers (`X-Accel-Expires`, `Surrogate-Control`)
* Logs blocked attempts when WP_DEBUG is enabled
* **Auto-updates** from GitHub releases (no WordPress.org dependency)

**Headers blocked:**

* X-HTTP-Method-Override
* X-HTTP-Method
* X-Method-Override

**Parameters blocked:**

* _method (GET/POST)

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`
2. Activate the plugin through the Plugins menu
3. No configuration required

== Changelog ==

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
