<?php
/**
 * Plugin Name: JT REST API Cache Poisoning Fix
 * Plugin URI: https://github.com/johnsandtaylor/jt-rest-api-cache-poisoning-fix
 * Description: Prevents cache poisoning attacks via X-HTTP-Method-Override header on REST API endpoints.
 * Version: 1.0.0
 * Author: Johns & Taylor
 * Author URI: https://johnsandtaylor.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 5.0
 * Requires PHP: 7.4
 *
 * Security Fix: Mitigates cache poisoning vulnerability where attackers can send
 * X-HTTP-Method-Override: HEAD headers to cause empty responses to be cached,
 * breaking the REST API for unauthenticated users.
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class JT_REST_Cache_Poisoning_Fix
 *
 * Handles the mitigation of cache poisoning attacks on the WordPress REST API.
 */
class JT_REST_Cache_Poisoning_Fix
{
    /**
     * Plugin version.
     *
     * @var string
     */
    public const VERSION = '1.0.0';

    /**
     * Headers that can be used for method override attacks.
     *
     * @var array
     */
    private const OVERRIDE_HEADERS = [
        'HTTP_X_HTTP_METHOD_OVERRIDE',
        'HTTP_X_HTTP_METHOD',
        'HTTP_X_METHOD_OVERRIDE',
    ];

    /**
     * Initialize the plugin.
     */
    public function __construct()
    {
        // Run as early as possible to strip headers before WordPress processes them
        add_action('init', [$this, 'strip_method_override_headers'], 1);

        // Add Vary header to REST API responses as defense in depth
        add_action('rest_api_init', [$this, 'add_rest_api_headers'], 1);

        // Filter REST API response headers
        add_filter('rest_post_dispatch', [$this, 'filter_rest_response_headers'], 10, 3);
    }

    /**
     * Strip method override headers from the request.
     *
     * This prevents WordPress from treating a GET request as HEAD/PUT/DELETE/etc.
     * based on an attacker-controlled header.
     *
     * @return void
     */
    public function strip_method_override_headers(): void
    {
        // Only process for REST API requests
        if (!$this->is_rest_request()) {
            return;
        }

        // Remove override headers from $_SERVER
        foreach (self::OVERRIDE_HEADERS as $header) {
            if (isset($_SERVER[$header])) {
                // Log the attempt for security monitoring (optional)
                $this->log_override_attempt($header, $_SERVER[$header]);

                // Remove the header
                unset($_SERVER[$header]);
            }
        }
    }

    /**
     * Add security headers to REST API responses.
     *
     * @return void
     */
    public function add_rest_api_headers(): void
    {
        // Add Vary header to ensure caches differentiate by these headers
        add_filter('rest_send_nocache_headers', '__return_true');
    }

    /**
     * Filter REST API response headers for cache poisoning prevention.
     *
     * @param WP_REST_Response $response The response object.
     * @param WP_REST_Server   $server   The REST server instance.
     * @param WP_REST_Request  $request  The request object.
     * @return WP_REST_Response Modified response object.
     */
    public function filter_rest_response_headers($response, $server, $request): WP_REST_Response
    {
        if (!$response instanceof WP_REST_Response) {
            return $response;
        }

        // Add Vary header to prevent cache poisoning
        // This tells caches to store separate versions based on these headers
        $existing_vary = $response->get_headers()['Vary'] ?? '';
        $vary_headers = ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override'];

        if ($existing_vary) {
            $vary_values = array_map('trim', explode(',', $existing_vary));
            $vary_headers = array_unique(array_merge($vary_values, $vary_headers));
        }

        $response->header('Vary', implode(', ', $vary_headers));

        // For unauthenticated requests, add cache control headers
        if (!is_user_logged_in()) {
            // These headers help prevent edge/CDN caching of potentially poisoned responses
            $response->header('Cache-Control', 'no-cache, must-revalidate, max-age=0');
            $response->header('Pragma', 'no-cache');
        }

        return $response;
    }

    /**
     * Check if the current request is a REST API request.
     *
     * @return bool True if this is a REST API request.
     */
    private function is_rest_request(): bool
    {
        // Check if REST API constant is defined (set by WordPress during REST requests)
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }

        // Check the request URI for REST API path
        $rest_prefix = rest_get_url_prefix();

        if (empty($rest_prefix)) {
            $rest_prefix = 'wp-json';
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

        // Check if the request URI contains the REST API prefix
        return (
            strpos($request_uri, '/' . $rest_prefix . '/') !== false ||
            strpos($request_uri, '/' . $rest_prefix) !== false
        );
    }

    /**
     * Log method override attempts for security monitoring.
     *
     * @param string $header The header name that was attempted.
     * @param string $value  The value of the header.
     * @return void
     */
    private function log_override_attempt(string $header, string $value): void
    {
        // Only log if WP_DEBUG is enabled to avoid filling up logs in production
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }

        $log_message = sprintf(
            '[JT Cache Poisoning Fix] Blocked method override attempt - Header: %s, Value: %s, IP: %s, URI: %s',
            $header,
            sanitize_text_field($value),
            $this->get_client_ip(),
            isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : 'unknown'
        );

        error_log($log_message); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
    }

    /**
     * Get the client IP address.
     *
     * @return string The client IP address.
     */
    private function get_client_ip(): string
    {
        $ip_headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_FORWARDED_FOR',      // Proxy/Load balancer
            'HTTP_X_REAL_IP',            // Nginx proxy
            'REMOTE_ADDR',               // Direct connection
        ];

        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                // X-Forwarded-For can contain multiple IPs; get the first one
                $ip = explode(',', sanitize_text_field(wp_unslash($_SERVER[$header])))[0];
                $ip = trim($ip);

                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return 'unknown';
    }
}

// Initialize the plugin
new JT_REST_Cache_Poisoning_Fix();

/**
 * Activation hook - flush rewrite rules to ensure REST API works correctly.
 */
register_activation_hook(__FILE__, function () {
    flush_rewrite_rules();
});

/**
 * Deactivation hook - flush rewrite rules.
 */
register_deactivation_hook(__FILE__, function () {
    flush_rewrite_rules();
});
