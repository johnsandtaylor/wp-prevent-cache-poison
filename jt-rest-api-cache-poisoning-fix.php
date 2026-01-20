<?php
/**
 * Plugin Name: JT REST API Cache Poisoning Fix
 * Plugin URI: https://github.com/johnsandtaylor/wp-prevent-cache-poison
 * Description: Prevents cache poisoning attacks via X-HTTP-Method-Override header on REST API endpoints.
 * Version: 1.2.0
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
 *
 * v1.2.0 Enhancement: Rejects requests with method override headers BEFORE processing,
 * returning a 400 Bad Request with no-cache headers to prevent upstream caches (like
 * Pagely ARES) from storing poisoned responses.
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// CRITICAL: Check for override headers IMMEDIATELY and reject with 400 + no-cache
// This must happen before ANY caching layer can store the response
JT_REST_Cache_Poisoning_Fix::early_reject_override_requests();

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
    public const VERSION = '1.2.0';

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
     * Query/POST parameters that can be used for method override attacks.
     * Some frameworks (Laravel, Rails) support _method parameter.
     *
     * @var array
     */
    private const OVERRIDE_PARAMS = [
        '_method',
        '_METHOD',
    ];

    /**
     * Early rejection of requests with method override headers.
     * Called immediately when plugin file is loaded - BEFORE WordPress processes anything.
     *
     * CRITICAL: This method REJECTS requests containing override headers with a 400 response
     * and aggressive no-cache headers. This prevents upstream caches (like Pagely ARES)
     * from storing any response for these malicious requests.
     *
     * The key insight is that stripping headers doesn't prevent cache poisoning because:
     * 1. The cache key is computed BEFORE the request reaches WordPress
     * 2. The cache stores whatever response WordPress returns
     * 3. If we just strip headers, we return a normal 200 response that gets cached
     *
     * By returning 400 + no-cache, we ensure:
     * 1. The poisoned request fails (not cached as success)
     * 2. Cache headers tell ARES not to store this response
     * 3. Legitimate requests without override headers work normally
     *
     * @return void
     */
    public static function early_reject_override_requests(): void
    {
        // Check if this looks like a REST API request (basic check without WP functions)
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($request_uri, '/wp-json') === false && strpos($request_uri, '/wp/v2') === false) {
            return;
        }

        $detected_override = null;
        $detected_value = null;

        // Check for override headers
        foreach (self::OVERRIDE_HEADERS as $header) {
            if (isset($_SERVER[$header]) && !empty($_SERVER[$header])) {
                $detected_override = $header;
                $detected_value = $_SERVER[$header];
                break;
            }
        }

        // Check for _method parameters if no header found
        if ($detected_override === null) {
            foreach (self::OVERRIDE_PARAMS as $param) {
                if (isset($_GET[$param]) && !empty($_GET[$param])) {
                    $detected_override = 'GET[' . $param . ']';
                    $detected_value = $_GET[$param];
                    break;
                }
                if (isset($_POST[$param]) && !empty($_POST[$param])) {
                    $detected_override = 'POST[' . $param . ']';
                    $detected_value = $_POST[$param];
                    break;
                }
            }
        }

        // If override attempt detected, reject the request immediately
        if ($detected_override !== null) {
            self::reject_request($detected_override, $detected_value);
        }

        // Also strip headers as defense in depth (for any edge cases that slip through)
        foreach (self::OVERRIDE_HEADERS as $header) {
            if (isset($_SERVER[$header])) {
                unset($_SERVER[$header]);
            }
        }

        foreach (self::OVERRIDE_PARAMS as $param) {
            unset($_GET[$param], $_POST[$param], $_REQUEST[$param]);
        }
    }

    /**
     * Reject a request with method override attempt.
     * Sends 400 Bad Request with aggressive no-cache headers to prevent cache poisoning.
     *
     * @param string $header The detected override header/parameter.
     * @param string $value  The value that was attempted.
     * @return void
     */
    private static function reject_request(string $header, string $value): void
    {
        // Log the attempt if WP_DEBUG is available (may not be loaded yet)
        if (defined('WP_DEBUG') && WP_DEBUG) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log(sprintf(
                '[JT Cache Poisoning Fix] REJECTED request with method override - Header: %s, Value: %s, IP: %s, URI: %s',
                $header,
                substr($value, 0, 50), // Truncate for safety
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['REQUEST_URI'] ?? 'unknown'
            ));
        }

        // Clear any output buffers
        while (ob_get_level()) {
            ob_end_clean();
        }

        // Set HTTP response code to 400 Bad Request
        http_response_code(400);

        // CRITICAL: Send aggressive no-cache headers to prevent ANY caching
        // These headers tell Pagely ARES (and any other cache) NOT to store this response
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
        header('Pragma: no-cache');
        header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');

        // Pagely-specific: Tell ARES to skip caching this response
        header('X-Accel-Expires: 0');
        header('Surrogate-Control: no-store');

        // Add Vary header to ensure cache key differentiation (defense in depth)
        header('Vary: X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override, Accept-Encoding');

        // Set content type
        header('Content-Type: application/json; charset=UTF-8');

        // Return error response
        $response = [
            'code'    => 'method_override_not_allowed',
            'message' => 'HTTP method override headers are not permitted on this endpoint.',
            'data'    => [
                'status' => 400,
            ],
        ];

        echo json_encode($response, JSON_UNESCAPED_SLASHES);

        // Terminate immediately - do not process further
        exit;
    }

    /**
     * Legacy method - kept for backwards compatibility but now calls the rejection method.
     * @deprecated Use early_reject_override_requests() instead.
     * @return void
     */
    public static function early_strip_headers(): void
    {
        self::early_reject_override_requests();
    }

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
     * based on an attacker-controlled header. Also strips _method parameters.
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

        // Remove _method parameters (backup - early_strip_headers should catch these first)
        foreach (self::OVERRIDE_PARAMS as $param) {
            if (isset($_GET[$param])) {
                $this->log_override_attempt('GET[' . $param . ']', $_GET[$param]);
                unset($_GET[$param]);
            }
            if (isset($_POST[$param])) {
                $this->log_override_attempt('POST[' . $param . ']', $_POST[$param]);
                unset($_POST[$param]);
            }
            if (isset($_REQUEST[$param])) {
                unset($_REQUEST[$param]);
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

        // For unauthenticated requests, add aggressive cache control headers
        // This ensures dynamic API responses are not cached by edge caches
        if (!is_user_logged_in()) {
            // Standard HTTP cache control
            $response->header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, private');
            $response->header('Pragma', 'no-cache');
            $response->header('Expires', 'Thu, 01 Jan 1970 00:00:00 GMT');

            // Pagely ARES specific headers
            $response->header('X-Accel-Expires', '0');
            $response->header('Surrogate-Control', 'no-store');
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
     * Get the client IP address for logging purposes.
     *
     * SECURITY NOTE: These headers can be spoofed by attackers. This is only used
     * for logging/monitoring, not for any security decisions. Take logged IPs
     * with appropriate skepticism during incident investigation.
     *
     * @return string The client IP address (may be spoofed).
     */
    private function get_client_ip(): string
    {
        // Prefer REMOTE_ADDR as it's harder to spoof, fall back to proxy headers
        // if REMOTE_ADDR shows a known proxy/CDN range
        $ip_headers = [
            'REMOTE_ADDR',               // Direct connection (most reliable)
            'HTTP_CF_CONNECTING_IP',     // Cloudflare (if behind CF)
            'HTTP_X_REAL_IP',            // Nginx proxy
            'HTTP_X_FORWARDED_FOR',      // Proxy/Load balancer (easily spoofed)
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

// Initialize the GitHub update checker
new JT_REST_Cache_Poisoning_Fix_Updater();

/**
 * Class JT_REST_Cache_Poisoning_Fix_Updater
 *
 * Handles automatic updates from the GitHub repository.
 * Checks https://github.com/johnsandtaylor/wp-prevent-cache-poison/releases for new versions.
 */
class JT_REST_Cache_Poisoning_Fix_Updater
{
    /**
     * GitHub repository owner.
     */
    private const GITHUB_USER = 'johnsandtaylor';

    /**
     * GitHub repository name.
     */
    private const GITHUB_REPO = 'wp-prevent-cache-poison';

    /**
     * Plugin slug (folder name).
     */
    private const PLUGIN_SLUG = 'wp-prevent-cache-poison';

    /**
     * Plugin basename.
     *
     * @var string
     */
    private string $plugin_basename;

    /**
     * Cached GitHub release data.
     *
     * @var object|null
     */
    private ?object $github_response = null;

    /**
     * Initialize the updater.
     */
    public function __construct()
    {
        $this->plugin_basename = plugin_basename(__FILE__);

        // Hook into the WordPress update system
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_update']);
        add_filter('plugins_api', [$this, 'plugin_info'], 10, 3);
        add_filter('upgrader_post_install', [$this, 'after_install'], 10, 3);

        // Add a "Check for updates" link on the plugins page
        add_filter('plugin_row_meta', [$this, 'plugin_row_meta'], 10, 2);
    }

    /**
     * Check GitHub for a new release.
     *
     * @param object $transient The update_plugins transient.
     * @return object Modified transient with update info if available.
     */
    public function check_for_update(object $transient): object
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        $remote_version = $this->get_remote_version();

        if ($remote_version && version_compare(JT_REST_Cache_Poisoning_Fix::VERSION, $remote_version, '<')) {
            $response = $this->get_github_response();

            $transient->response[$this->plugin_basename] = (object) [
                'slug'        => self::PLUGIN_SLUG,
                'plugin'      => $this->plugin_basename,
                'new_version' => $remote_version,
                'url'         => 'https://github.com/' . self::GITHUB_USER . '/' . self::GITHUB_REPO,
                'package'     => $response->zipball_url ?? '',
                'icons'       => [],
                'banners'     => [],
                'tested'      => '',
                'requires'    => '5.0',
                'requires_php'=> '7.4',
            ];
        }

        return $transient;
    }

    /**
     * Provide plugin information for the WordPress plugin details popup.
     *
     * @param false|object|array $result The result object or array.
     * @param string             $action The API action being performed.
     * @param object             $args   Plugin API arguments.
     * @return false|object Plugin info or false if not our plugin.
     */
    public function plugin_info($result, string $action, object $args)
    {
        if ($action !== 'plugin_information') {
            return $result;
        }

        if (!isset($args->slug) || $args->slug !== self::PLUGIN_SLUG) {
            return $result;
        }

        $response = $this->get_github_response();

        if (!$response) {
            return $result;
        }

        return (object) [
            'name'              => 'JT REST API Cache Poisoning Fix',
            'slug'              => self::PLUGIN_SLUG,
            'version'           => ltrim($response->tag_name ?? '', 'v'),
            'author'            => '<a href="https://johnsandtaylor.com">Johns & Taylor</a>',
            'author_profile'    => 'https://johnsandtaylor.com',
            'homepage'          => 'https://github.com/' . self::GITHUB_USER . '/' . self::GITHUB_REPO,
            'short_description' => 'Prevents cache poisoning attacks via X-HTTP-Method-Override header on REST API endpoints.',
            'sections'          => [
                'description'  => 'This plugin mitigates cache poisoning vulnerabilities where attackers can send X-HTTP-Method-Override headers to cause malformed responses to be cached by upstream caching layers (like Pagely ARES).',
                'installation' => 'Upload the plugin folder to /wp-content/plugins/ and activate.',
                'changelog'    => $this->format_changelog($response->body ?? ''),
            ],
            'download_link'     => $response->zipball_url ?? '',
            'requires'          => '5.0',
            'tested'            => '',
            'requires_php'      => '7.4',
            'last_updated'      => $response->published_at ?? '',
            'downloaded'        => 0,
            'active_installs'   => 0,
        ];
    }

    /**
     * Handle post-installation tasks.
     * Renames the extracted folder to match the expected plugin slug.
     *
     * @param bool  $response   Installation response.
     * @param array $hook_extra Extra arguments passed to hooked filters.
     * @param array $result     Installation result data.
     * @return array Modified result.
     */
    public function after_install(bool $response, array $hook_extra, array $result): array
    {
        global $wp_filesystem;

        // Check if this is our plugin being updated
        if (!isset($hook_extra['plugin']) || $hook_extra['plugin'] !== $this->plugin_basename) {
            return $result;
        }

        $install_directory = plugin_dir_path(__FILE__);
        $wp_filesystem->move($result['destination'], $install_directory);
        $result['destination'] = $install_directory;

        // Reactivate the plugin
        activate_plugin($this->plugin_basename);

        return $result;
    }

    /**
     * Add plugin row meta links.
     *
     * @param array  $links Plugin row meta links.
     * @param string $file  Plugin file path.
     * @return array Modified links.
     */
    public function plugin_row_meta(array $links, string $file): array
    {
        if ($file === $this->plugin_basename) {
            $links[] = sprintf(
                '<a href="%s">%s</a>',
                esc_url('https://github.com/' . self::GITHUB_USER . '/' . self::GITHUB_REPO . '/releases'),
                esc_html__('View releases on GitHub', 'jt-rest-cache-fix')
            );
        }

        return $links;
    }

    /**
     * Get the remote version from GitHub.
     *
     * @return string|null Version string or null if unavailable.
     */
    private function get_remote_version(): ?string
    {
        $response = $this->get_github_response();

        if (!$response || !isset($response->tag_name)) {
            return null;
        }

        // Remove 'v' prefix if present (e.g., 'v1.2.0' -> '1.2.0')
        return ltrim($response->tag_name, 'v');
    }

    /**
     * Fetch and cache the latest release from GitHub API.
     *
     * @return object|null GitHub API response or null on failure.
     */
    private function get_github_response(): ?object
    {
        if ($this->github_response !== null) {
            return $this->github_response;
        }

        // Check for cached response
        $cache_key = 'jt_cache_fix_github_response';
        $cached = get_transient($cache_key);

        if ($cached !== false) {
            $this->github_response = $cached;
            return $this->github_response;
        }

        // Fetch from GitHub API
        $url = sprintf(
            'https://api.github.com/repos/%s/%s/releases/latest',
            self::GITHUB_USER,
            self::GITHUB_REPO
        );

        $response = wp_remote_get($url, [
            'headers' => [
                'Accept'     => 'application/vnd.github.v3+json',
                'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url'),
            ],
            'timeout' => 10,
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Cache failure for 1 hour to avoid hammering the API
            set_transient($cache_key, null, HOUR_IN_SECONDS);
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body);

        if (!$data || !isset($data->tag_name)) {
            set_transient($cache_key, null, HOUR_IN_SECONDS);
            return null;
        }

        // Cache successful response for 12 hours
        set_transient($cache_key, $data, 12 * HOUR_IN_SECONDS);
        $this->github_response = $data;

        return $this->github_response;
    }

    /**
     * Format the changelog from GitHub release notes.
     *
     * @param string $body Release body/notes from GitHub.
     * @return string Formatted changelog HTML.
     */
    private function format_changelog(string $body): string
    {
        if (empty($body)) {
            return '<p>See <a href="https://github.com/' . self::GITHUB_USER . '/' . self::GITHUB_REPO . '/releases">GitHub releases</a> for full changelog.</p>';
        }

        // Convert markdown to basic HTML
        $html = esc_html($body);
        $html = nl2br($html);

        // Convert markdown headers
        $html = preg_replace('/^### (.+)$/m', '<h4>$1</h4>', $html);
        $html = preg_replace('/^## (.+)$/m', '<h3>$1</h3>', $html);

        // Convert markdown bold
        $html = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $html);

        // Convert markdown links
        $html = preg_replace('/\[([^\]]+)\]\(([^)]+)\)/', '<a href="$2">$1</a>', $html);

        return $html;
    }
}

/**
 * Activation hook - flush rewrite rules to ensure REST API works correctly.
 */
register_activation_hook(__FILE__, function () {
    flush_rewrite_rules();

    // Clear the GitHub update cache on activation
    delete_transient('jt_cache_fix_github_response');
});

/**
 * Deactivation hook - flush rewrite rules.
 */
register_deactivation_hook(__FILE__, function () {
    flush_rewrite_rules();

    // Clear the GitHub update cache on deactivation
    delete_transient('jt_cache_fix_github_response');
});
