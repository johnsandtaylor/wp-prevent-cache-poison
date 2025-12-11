=== JT REST API Cache Poisoning Fix ===
Contributors: johnsandtaylor
Tags: security, rest-api, cache, vulnerability
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Prevents cache poisoning attacks via X-HTTP-Method-Override header on REST API endpoints.

== Description ==

This plugin mitigates a cache poisoning vulnerability where attackers can send `X-HTTP-Method-Override: HEAD` headers to cause empty responses to be cached, breaking the REST API for unauthenticated users.

**What it does:**

* Strips method override headers from REST API requests
* Adds Vary headers to prevent cache key collisions
* Adds cache control headers for unauthenticated REST requests
* Logs blocked attempts when WP_DEBUG is enabled

**Headers blocked:**

* X-HTTP-Method-Override
* X-HTTP-Method
* X-Method-Override

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`
2. Activate the plugin through the Plugins menu
3. No configuration required

== Changelog ==

= 1.0.0 =
* Initial release
* Strips method override headers from REST API requests
* Adds Vary and Cache-Control headers for defense in depth
* Security logging when WP_DEBUG enabled
