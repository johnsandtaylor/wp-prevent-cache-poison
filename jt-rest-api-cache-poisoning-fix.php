<?php
/**
 * Plugin Name: JT REST API Cache Poisoning Fix
 * Plugin URI: https://github.com/johnsandtaylor/wp-prevent-cache-poison
 * Description: Prevents cache poisoning attacks and restricts REST API endpoint exposure for enhanced security.
 * Version: 1.3.2
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
 *
 * v1.3.0 Enhancement: Adds REST API access controls to restrict public access to
 * /wp-json/ endpoint. Supports authentication requirements, IP whitelisting,
 * and namespace/route restrictions to reduce attack surface exposure.
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
    public const VERSION = '1.3.2';

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
     * Default plugin settings.
     *
     * @var array
     */
    private const DEFAULT_SETTINGS = [
        'restrict_root_endpoint'    => true,   // Restrict /wp-json/ root endpoint
        'require_authentication'    => false,  // Require auth for all REST API
        'ip_whitelist_enabled'      => false,  // Enable IP whitelist
        'ip_whitelist'              => [],     // Whitelisted IPs/CIDRs
        'allowed_namespaces'        => [],     // Empty = all allowed; populated = only these
        'blocked_namespaces'        => [],     // Namespaces to block entirely
        'allowed_public_routes'     => [       // Routes that remain public even with auth required
            '/wp/v2/posts',
            '/wp/v2/pages',
            '/wp/v2/categories',
            '/wp/v2/tags',
            '/oembed/',
        ],
        'hide_user_endpoints'       => true,   // Hide /wp/v2/users from unauthenticated
        'disable_application_passwords' => false, // Disable app passwords feature
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
     * Cached settings.
     *
     * @var array|null
     */
    private ?array $settings = null;

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

        // REST API access control hooks
        add_filter('rest_authentication_errors', [$this, 'check_rest_api_access'], 99);
        add_filter('rest_endpoints', [$this, 'filter_rest_endpoints'], 10);
        add_filter('rest_index', [$this, 'filter_rest_index'], 10);

        // Optionally disable application passwords
        if ($this->get_setting('disable_application_passwords')) {
            add_filter('wp_is_application_passwords_available', '__return_false');
        }

        // Admin settings page
        if (is_admin()) {
            add_action('admin_menu', [$this, 'add_admin_menu']);
            add_action('admin_init', [$this, 'register_settings']);
            add_action('admin_init', [$this, 'handle_force_update_check']);
        }
    }

    /**
     * Handle force update check request.
     *
     * @return void
     */
    public function handle_force_update_check(): void
    {
        if (
            !isset($_GET['jt_force_update_check']) ||
            !isset($_GET['_wpnonce']) ||
            !wp_verify_nonce($_GET['_wpnonce'], 'jt_force_update_check')
        ) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        // Clear the cached GitHub response
        delete_transient('jt_cache_fix_github_response');

        // Clear WordPress plugin update transient to force a fresh check
        delete_site_transient('update_plugins');

        // Redirect back to the settings page with a success message
        wp_safe_redirect(add_query_arg(
            ['page' => 'jt-rest-api-security', 'update_checked' => '1'],
            admin_url('options-general.php')
        ));
        exit;
    }

    /**
     * Get plugin settings with defaults.
     *
     * @return array Plugin settings.
     */
    public function get_settings(): array
    {
        if ($this->settings === null) {
            $saved = get_option('jt_rest_api_security_settings', []);
            $this->settings = wp_parse_args($saved, self::DEFAULT_SETTINGS);
        }
        return $this->settings;
    }

    /**
     * Get a specific setting value.
     *
     * @param string $key Setting key.
     * @return mixed Setting value.
     */
    public function get_setting(string $key)
    {
        $settings = $this->get_settings();
        return $settings[$key] ?? (self::DEFAULT_SETTINGS[$key] ?? null);
    }

    /**
     * Check REST API access based on configured restrictions.
     *
     * @param WP_Error|null|true $errors Current authentication status.
     * @return WP_Error|null|true Modified authentication status.
     */
    public function check_rest_api_access($errors)
    {
        // If already errored, don't override
        if (is_wp_error($errors)) {
            return $errors;
        }

        // Logged-in users bypass most restrictions
        if (is_user_logged_in()) {
            return $errors;
        }

        $request_uri = $_SERVER['REQUEST_URI'] ?? '';

        // Check IP whitelist first (if enabled, non-whitelisted IPs are blocked)
        if ($this->get_setting('ip_whitelist_enabled')) {
            $whitelist = $this->get_setting('ip_whitelist');
            if (!empty($whitelist) && !$this->is_ip_whitelisted($whitelist)) {
                return new WP_Error(
                    'rest_forbidden_ip',
                    __('REST API access is not available from your location.', 'jt-rest-cache-fix'),
                    ['status' => 403]
                );
            }
        }

        // Check if this is the root /wp-json/ endpoint
        if ($this->get_setting('restrict_root_endpoint') && $this->is_root_endpoint($request_uri)) {
            return new WP_Error(
                'rest_index_disabled',
                __('The REST API index is not available.', 'jt-rest-cache-fix'),
                ['status' => 403]
            );
        }

        // Check if authentication is required for all requests
        if ($this->get_setting('require_authentication')) {
            // Check if this route is in the allowed public routes
            $allowed_public = $this->get_setting('allowed_public_routes');
            $is_public_route = false;

            foreach ($allowed_public as $route) {
                if (strpos($request_uri, $route) !== false) {
                    $is_public_route = true;
                    break;
                }
            }

            if (!$is_public_route) {
                return new WP_Error(
                    'rest_not_logged_in',
                    __('You must be authenticated to access this endpoint.', 'jt-rest-cache-fix'),
                    ['status' => 401]
                );
            }
        }

        // Check namespace restrictions
        $blocked_namespaces = $this->get_setting('blocked_namespaces');
        if (!empty($blocked_namespaces)) {
            foreach ($blocked_namespaces as $namespace) {
                if (strpos($request_uri, '/wp-json/' . $namespace) !== false) {
                    return new WP_Error(
                        'rest_namespace_blocked',
                        __('This API namespace is not available.', 'jt-rest-cache-fix'),
                        ['status' => 403]
                    );
                }
            }
        }

        return $errors;
    }

    /**
     * Check if the request is to the root /wp-json/ endpoint.
     *
     * @param string $request_uri The request URI.
     * @return bool True if root endpoint.
     */
    private function is_root_endpoint(string $request_uri): bool
    {
        $rest_prefix = rest_get_url_prefix();
        $pattern = '#/' . preg_quote($rest_prefix, '#') . '/?(\?.*)?$#';
        return (bool) preg_match($pattern, $request_uri);
    }

    /**
     * Check if the client IP is in the whitelist.
     *
     * @param array $whitelist Array of IPs or CIDR ranges.
     * @return bool True if whitelisted.
     */
    private function is_ip_whitelisted(array $whitelist): bool
    {
        $client_ip = $this->get_client_ip();

        if ($client_ip === 'unknown') {
            return false;
        }

        foreach ($whitelist as $allowed) {
            $allowed = trim($allowed);

            // Check for CIDR notation
            if (strpos($allowed, '/') !== false) {
                if ($this->ip_in_cidr($client_ip, $allowed)) {
                    return true;
                }
            } elseif ($client_ip === $allowed) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP is within a CIDR range.
     *
     * @param string $ip   The IP address to check.
     * @param string $cidr The CIDR range.
     * @return bool True if IP is in range.
     */
    private function ip_in_cidr(string $ip, string $cidr): bool
    {
        list($subnet, $mask) = explode('/', $cidr);

        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - (int) $mask);

        $subnet_long &= $mask_long;

        return ($ip_long & $mask_long) === $subnet_long;
    }

    /**
     * Filter REST API endpoints to hide sensitive ones from unauthenticated users.
     *
     * @param array $endpoints The available endpoints.
     * @return array Modified endpoints.
     */
    public function filter_rest_endpoints(array $endpoints): array
    {
        // Hide user endpoints from unauthenticated users
        if ($this->get_setting('hide_user_endpoints') && !is_user_logged_in()) {
            unset($endpoints['/wp/v2/users']);
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
            unset($endpoints['/wp/v2/users/me']);
        }

        // Remove blocked namespaces entirely
        $blocked_namespaces = $this->get_setting('blocked_namespaces');
        if (!empty($blocked_namespaces) && !is_user_logged_in()) {
            foreach ($endpoints as $route => $data) {
                foreach ($blocked_namespaces as $namespace) {
                    if (strpos($route, '/' . $namespace) === 0) {
                        unset($endpoints[$route]);
                        break;
                    }
                }
            }
        }

        return $endpoints;
    }

    /**
     * Filter the REST API index response to hide metadata from unauthenticated users.
     *
     * @param WP_REST_Response $response The response object.
     * @return WP_REST_Response Modified response.
     */
    public function filter_rest_index($response): WP_REST_Response
    {
        if (is_user_logged_in()) {
            return $response;
        }

        // If root endpoint is restricted, this shouldn't be reached,
        // but as defense in depth, return minimal info
        if ($this->get_setting('restrict_root_endpoint')) {
            $data = $response->get_data();

            // Remove sensitive metadata
            unset($data['namespaces']);
            unset($data['routes']);
            unset($data['authentication']);

            // Keep only basic info
            $minimal_data = [
                'name'        => $data['name'] ?? get_bloginfo('name'),
                'description' => $data['description'] ?? get_bloginfo('description'),
                'url'         => $data['url'] ?? home_url(),
                'home'        => $data['home'] ?? home_url(),
                'gmt_offset'  => $data['gmt_offset'] ?? get_option('gmt_offset'),
                'timezone_string' => $data['timezone_string'] ?? get_option('timezone_string'),
            ];

            $response->set_data($minimal_data);
        }

        return $response;
    }

    /**
     * Add admin menu page.
     *
     * @return void
     */
    public function add_admin_menu(): void
    {
        add_options_page(
            __('REST API Security', 'jt-rest-cache-fix'),
            __('REST API Security', 'jt-rest-cache-fix'),
            'manage_options',
            'jt-rest-api-security',
            [$this, 'render_admin_page']
        );
    }

    /**
     * Register plugin settings.
     *
     * @return void
     */
    public function register_settings(): void
    {
        register_setting(
            'jt_rest_api_security',
            'jt_rest_api_security_settings',
            [
                'type'              => 'array',
                'sanitize_callback' => [$this, 'sanitize_settings'],
                'default'           => self::DEFAULT_SETTINGS,
            ]
        );
    }

    /**
     * Sanitize settings input.
     *
     * @param array $input Raw input.
     * @return array Sanitized settings.
     */
    public function sanitize_settings(array $input): array
    {
        $sanitized = [];

        // Boolean settings
        $sanitized['restrict_root_endpoint'] = !empty($input['restrict_root_endpoint']);
        $sanitized['require_authentication'] = !empty($input['require_authentication']);
        $sanitized['ip_whitelist_enabled'] = !empty($input['ip_whitelist_enabled']);
        $sanitized['hide_user_endpoints'] = !empty($input['hide_user_endpoints']);
        $sanitized['disable_application_passwords'] = !empty($input['disable_application_passwords']);

        // IP whitelist (one per line or already an array)
        $sanitized['ip_whitelist'] = [];
        if (!empty($input['ip_whitelist'])) {
            // Handle both string (from form) and array (from existing settings)
            $lines = is_array($input['ip_whitelist'])
                ? $input['ip_whitelist']
                : explode("\n", $input['ip_whitelist']);
            foreach ($lines as $line) {
                $line = trim($line);
                if (!empty($line) && (filter_var($line, FILTER_VALIDATE_IP) || preg_match('#^\d+\.\d+\.\d+\.\d+/\d+$#', $line))) {
                    $sanitized['ip_whitelist'][] = $line;
                }
            }
        }

        // Namespace arrays (one per line or already an array)
        $sanitized['allowed_namespaces'] = [];
        if (!empty($input['allowed_namespaces'])) {
            $lines = is_array($input['allowed_namespaces'])
                ? $input['allowed_namespaces']
                : explode("\n", $input['allowed_namespaces']);
            foreach ($lines as $line) {
                $line = sanitize_text_field(trim($line));
                if (!empty($line)) {
                    $sanitized['allowed_namespaces'][] = $line;
                }
            }
        }

        $sanitized['blocked_namespaces'] = [];
        if (!empty($input['blocked_namespaces'])) {
            $lines = is_array($input['blocked_namespaces'])
                ? $input['blocked_namespaces']
                : explode("\n", $input['blocked_namespaces']);
            foreach ($lines as $line) {
                $line = sanitize_text_field(trim($line));
                if (!empty($line)) {
                    $sanitized['blocked_namespaces'][] = $line;
                }
            }
        }

        // Public routes (one per line or already an array)
        $sanitized['allowed_public_routes'] = [];
        if (!empty($input['allowed_public_routes'])) {
            $lines = is_array($input['allowed_public_routes'])
                ? $input['allowed_public_routes']
                : explode("\n", $input['allowed_public_routes']);
            foreach ($lines as $line) {
                $line = sanitize_text_field(trim($line));
                if (!empty($line)) {
                    $sanitized['allowed_public_routes'][] = $line;
                }
            }
        }

        // Clear cached settings
        $this->settings = null;

        return $sanitized;
    }

    /**
     * Render the admin settings page.
     *
     * @return void
     */
    public function render_admin_page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $settings = $this->get_settings();
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <?php if (isset($_GET['update_checked'])) : ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php _e('Update check completed. If a new version is available, you will see it on the Plugins page.', 'jt-rest-cache-fix'); ?></p>
                </div>
            <?php endif; ?>

            <div class="notice notice-info">
                <p>
                    <strong><?php _e('About this plugin:', 'jt-rest-cache-fix'); ?></strong>
                    <?php _e('This plugin provides security hardening for the WordPress REST API, including cache poisoning prevention and access controls.', 'jt-rest-cache-fix'); ?>
                </p>
            </div>

            <form method="post" action="options.php">
                <?php settings_fields('jt_rest_api_security'); ?>

                <h2><?php _e('Cache Poisoning Protection', 'jt-rest-cache-fix'); ?></h2>
                <p class="description">
                    <?php _e('Cache poisoning protection is always active. Requests with X-HTTP-Method-Override headers are automatically rejected with a 400 response.', 'jt-rest-cache-fix'); ?>
                </p>

                <h2><?php _e('REST API Access Controls', 'jt-rest-cache-fix'); ?></h2>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('Restrict Root Endpoint', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="jt_rest_api_security_settings[restrict_root_endpoint]" value="1" <?php checked($settings['restrict_root_endpoint']); ?> />
                                <?php _e('Block public access to /wp-json/ root endpoint', 'jt-rest-cache-fix'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Prevents unauthenticated users from viewing available API endpoints, namespaces, and routes. Recommended to reduce attack surface.', 'jt-rest-cache-fix'); ?>
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><?php _e('Hide User Endpoints', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="jt_rest_api_security_settings[hide_user_endpoints]" value="1" <?php checked($settings['hide_user_endpoints']); ?> />
                                <?php _e('Hide /wp/v2/users endpoints from unauthenticated requests', 'jt-rest-cache-fix'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Prevents username enumeration via the REST API.', 'jt-rest-cache-fix'); ?>
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><?php _e('Require Authentication', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="jt_rest_api_security_settings[require_authentication]" value="1" <?php checked($settings['require_authentication']); ?> />
                                <?php _e('Require authentication for all REST API requests', 'jt-rest-cache-fix'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Warning: This may break functionality for themes/plugins that use the REST API publicly. Configure allowed public routes below.', 'jt-rest-cache-fix'); ?>
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><?php _e('Allowed Public Routes', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <textarea name="jt_rest_api_security_settings[allowed_public_routes]" rows="5" cols="50" class="large-text code"><?php echo esc_textarea(implode("\n", $settings['allowed_public_routes'])); ?></textarea>
                            <p class="description">
                                <?php _e('Routes that remain accessible without authentication (one per line). Only applies when "Require Authentication" is enabled.', 'jt-rest-cache-fix'); ?>
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><?php _e('Blocked Namespaces', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <textarea name="jt_rest_api_security_settings[blocked_namespaces]" rows="3" cols="50" class="large-text code"><?php echo esc_textarea(implode("\n", $settings['blocked_namespaces'])); ?></textarea>
                            <p class="description">
                                <?php _e('API namespaces to completely block for unauthenticated users (one per line, e.g., "wp/v2", "custom/v1").', 'jt-rest-cache-fix'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <h2><?php _e('IP-Based Access Control', 'jt-rest-cache-fix'); ?></h2>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('Enable IP Whitelist', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="jt_rest_api_security_settings[ip_whitelist_enabled]" value="1" <?php checked($settings['ip_whitelist_enabled']); ?> />
                                <?php _e('Only allow REST API access from whitelisted IPs', 'jt-rest-cache-fix'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Warning: This will block all REST API access from non-whitelisted IPs for unauthenticated requests.', 'jt-rest-cache-fix'); ?>
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><?php _e('Whitelisted IPs', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <textarea name="jt_rest_api_security_settings[ip_whitelist]" rows="5" cols="50" class="large-text code"><?php echo esc_textarea(implode("\n", $settings['ip_whitelist'])); ?></textarea>
                            <p class="description">
                                <?php _e('One IP address or CIDR range per line (e.g., 192.168.1.1 or 10.0.0.0/8).', 'jt-rest-cache-fix'); ?>
                                <br>
                                <?php printf(__('Your current IP: %s', 'jt-rest-cache-fix'), '<code>' . esc_html($this->get_client_ip()) . '</code>'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <h2><?php _e('Additional Security', 'jt-rest-cache-fix'); ?></h2>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('Disable Application Passwords', 'jt-rest-cache-fix'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="jt_rest_api_security_settings[disable_application_passwords]" value="1" <?php checked($settings['disable_application_passwords']); ?> />
                                <?php _e('Disable the Application Passwords feature', 'jt-rest-cache-fix'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Application Passwords allow REST API authentication without exposing user credentials. Disable if not needed.', 'jt-rest-cache-fix'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>

            <hr>

            <h2><?php _e('Security Status', 'jt-rest-cache-fix'); ?></h2>
            <table class="widefat" style="max-width: 600px;">
                <tbody>
                    <tr>
                        <td><strong><?php _e('Cache Poisoning Protection', 'jt-rest-cache-fix'); ?></strong></td>
                        <td><span class="dashicons dashicons-yes-alt" style="color: green;"></span> <?php _e('Active', 'jt-rest-cache-fix'); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php _e('Root Endpoint Protection', 'jt-rest-cache-fix'); ?></strong></td>
                        <td>
                            <?php if ($settings['restrict_root_endpoint']) : ?>
                                <span class="dashicons dashicons-yes-alt" style="color: green;"></span> <?php _e('Active', 'jt-rest-cache-fix'); ?>
                            <?php else : ?>
                                <span class="dashicons dashicons-warning" style="color: orange;"></span> <?php _e('Disabled', 'jt-rest-cache-fix'); ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong><?php _e('User Endpoint Protection', 'jt-rest-cache-fix'); ?></strong></td>
                        <td>
                            <?php if ($settings['hide_user_endpoints']) : ?>
                                <span class="dashicons dashicons-yes-alt" style="color: green;"></span> <?php _e('Active', 'jt-rest-cache-fix'); ?>
                            <?php else : ?>
                                <span class="dashicons dashicons-warning" style="color: orange;"></span> <?php _e('Disabled', 'jt-rest-cache-fix'); ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong><?php _e('Authentication Required', 'jt-rest-cache-fix'); ?></strong></td>
                        <td>
                            <?php if ($settings['require_authentication']) : ?>
                                <span class="dashicons dashicons-yes-alt" style="color: green;"></span> <?php _e('Active', 'jt-rest-cache-fix'); ?>
                            <?php else : ?>
                                <span class="dashicons dashicons-info" style="color: blue;"></span> <?php _e('Public access allowed', 'jt-rest-cache-fix'); ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong><?php _e('IP Whitelist', 'jt-rest-cache-fix'); ?></strong></td>
                        <td>
                            <?php if ($settings['ip_whitelist_enabled'] && !empty($settings['ip_whitelist'])) : ?>
                                <span class="dashicons dashicons-yes-alt" style="color: green;"></span>
                                <?php printf(__('Active (%d IPs/ranges)', 'jt-rest-cache-fix'), count($settings['ip_whitelist'])); ?>
                            <?php else : ?>
                                <span class="dashicons dashicons-info" style="color: blue;"></span> <?php _e('Disabled', 'jt-rest-cache-fix'); ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                </tbody>
            </table>

            <h3><?php _e('Plugin Information', 'jt-rest-cache-fix'); ?></h3>
            <p>
                <strong><?php _e('Version:', 'jt-rest-cache-fix'); ?></strong> <?php echo esc_html(self::VERSION); ?><br>
                <strong><?php _e('Documentation:', 'jt-rest-cache-fix'); ?></strong>
                <a href="https://github.com/johnsandtaylor/wp-prevent-cache-poison" target="_blank">GitHub Repository</a>
            </p>

            <h3><?php _e('Updates', 'jt-rest-cache-fix'); ?></h3>
            <p>
                <?php
                $update_check_url = wp_nonce_url(
                    add_query_arg(
                        ['page' => 'jt-rest-api-security', 'jt_force_update_check' => '1'],
                        admin_url('options-general.php')
                    ),
                    'jt_force_update_check'
                );
                ?>
                <a href="<?php echo esc_url($update_check_url); ?>" class="button button-secondary">
                    <?php _e('Check for Updates', 'jt-rest-cache-fix'); ?>
                </a>
                <a href="https://github.com/johnsandtaylor/wp-prevent-cache-poison/releases" target="_blank" class="button button-secondary">
                    <?php _e('View Releases on GitHub', 'jt-rest-cache-fix'); ?>
                </a>
            </p>
            <p class="description">
                <?php _e('This plugin automatically checks for updates from GitHub. Click the button above to check immediately.', 'jt-rest-cache-fix'); ?>
            </p>
        </div>
        <?php
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
