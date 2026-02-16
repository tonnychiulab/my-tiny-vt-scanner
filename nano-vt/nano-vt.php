<?php

/**
 * Plugin Name: Nano VT Scanner
 * Description: An ultra-lightweight, secure, and smart VirusTotal API v3 integration for WordPress.
 * Version: 1.0.0
 * Author: BMI Security Team
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.9
 * Requires PHP: 8.3
 */

if (! defined('ABSPATH')) {
    exit;
}

class Nano_VT_Scanner
{
    private $option_name = 'nano_vt_settings';

    public function __construct()
    {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('rest_api_init', [$this, 'register_rest_routes']);
    }

    // 1. Menu
    public function add_admin_menu()
    {
        add_menu_page(
            __('Nano VT Scanner', 'nano-vt'),
            __('Nano VT Scanner', 'nano-vt'),
            'manage_options',
            'nano-vt',
            [$this, 'render_admin_page'],
            'dashicons-shield',
            99
        );
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
    }

    // 2. Settings
    public function register_settings()
    {
        register_setting('nano_vt_group', $this->option_name, [
            'sanitize_callback' => [$this, 'validate_api_key']
        ]);
    }

    public function validate_api_key($input)
    {
        // 1. Sanitize
        $new_input = [];
        // Handle input array structure: name="nano_vt_settings[api_key]"
        $key = sanitize_text_field($input['api_key'] ?? '');
        $new_input['api_key'] = $key;

        // 2. Check Empty
        if (empty($key)) {
            add_settings_error('nano_vt_messages', 'nano_vt_error', __('API Key cannot be empty!', 'nano-vt'), 'error');
            // Return existing option to prevent overwrite with empty
            return get_option($this->option_name);
        }

        // 3. Verify with VT (Test against Google DNS)
        $response = wp_remote_get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', [
            'headers' => ['x-apikey' => $key],
            'timeout' => 10
        ]);

        $code = wp_remote_retrieve_response_code($response);

        if (is_wp_error($response) || $code !== 200) {
            $msg = ($code === 401 || $code === 403)
                ? __('Invalid API Key (Unauthorized).', 'nano-vt')
                : __('Failed to connect to VirusTotal or quota exceeded.', 'nano-vt');

            add_settings_error('nano_vt_messages', 'nano_vt_error', $msg, 'error');
            return get_option($this->option_name);
        }

        // 4. Success
        add_settings_error('nano_vt_messages', 'nano_vt_success', __('API Key verified successfully!', 'nano-vt'), 'updated');
        return $new_input;
    }

    // 3. REST API
    public function register_rest_routes()
    {
        register_rest_route('nano-vt/v1', '/scan', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_rest_query'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            }
        ]);
    }

    public function handle_rest_query($request)
    {
        $target = sanitize_text_field($request->get_param('target'));
        $nonce = $request->get_header('x-wp-nonce');

        if (! wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_Error('invalid_nonce', __('Invalid Nonce', 'nano-vt'), ['status' => 403]);
        }

        if (empty($target)) {
            return new WP_Error('empty_target', __('Target cannot be empty', 'nano-vt'), ['status' => 400]);
        }

        $options = get_option($this->option_name);
        $api_key = $options['api_key'] ?? '';

        if (empty($api_key)) {
            return new WP_Error('missing_apikey', __('API Key is missing', 'nano-vt'), ['status' => 400]);
        }

        // --- Smart Detection Logic ---
        $type = 'unknown';
        $api_url = '';
        $clean_target = $target;

        $ip_regex = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';

        if (preg_match($ip_regex, $target)) {
            $type = 'ip';
            $api_url = "https://www.virustotal.com/api/v3/ip_addresses/{$target}";
        } else {
            $clean_target = preg_replace('#^https?://#', '', $target);
            $clean_target = rtrim($clean_target, '/');

            if (strpos($clean_target, '/') === false) {
                $type = 'domain';
                $api_url = "https://www.virustotal.com/api/v3/domains/{$clean_target}";
            } else {
                $type = 'url';
                if (strpos($target, 'http') !== 0) {
                    $target = 'http://' . $target;
                }
                if (! filter_var($target, FILTER_VALIDATE_URL)) {
                    return new WP_Error('invalid_target', __('Invalid Input Format', 'nano-vt'), ['status' => 400]);
                }
                $url_id = rtrim(strtr(base64_encode($target), '+/', '-_'), '=');
                $api_url = "https://www.virustotal.com/api/v3/urls/{$url_id}";
            }
        }

        // --- Caching ---
        $cache_key = 'nano_vt_' . md5($target . $type);
        $cached_data = get_transient($cache_key);

        if ($cached_data) {
            return rest_ensure_response($cached_data);
        }

        // --- API Request ---
        $response = wp_remote_get($api_url, [
            'headers' => ['x-apikey' => $api_key],
            'timeout' => 20
        ]);

        if (is_wp_error($response)) {
            return new WP_Error('api_error', __('Connection Failed', 'nano-vt'), ['status' => 500]);
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (isset($body['data']['attributes'])) {
            $data = $body['data']['attributes'];
            $data['_tiny_type'] = $type;
            $data['_tiny_target_clean'] = $clean_target;

            set_transient($cache_key, $data, 3600);
            return rest_ensure_response($data);
        } else {
            return new WP_Error('vt_error', $body['error']['message'] ?? __('Unknown API Error', 'nano-vt'), ['status' => 400]);
        }
    }

    // 4. Assets
    public function enqueue_assets($hook)
    {
        if ($hook !== 'toplevel_page_nano-vt-scanner') {
            return;
        }

        wp_enqueue_style('nano-vt-css', plugin_dir_url(__FILE__) . 'assets/css/admin-style.css', [], '1.0.0');
        wp_enqueue_script('nano-vt-js', plugin_dir_url(__FILE__) . 'assets/js/admin-script.js', ['jquery'], '1.0.0', true);

        wp_localize_script('nano-vt-js', 'nanoVars', [
            'api_url' => rest_url('nano-vt/v1/scan'),
            'nonce'   => wp_create_nonce('wp_rest'),
            'i18n'    => [
                'scanning' => __('Scanning...', 'nano-vt'),
                'report'   => __('Scan Report', 'nano-vt'),
                'error'    => __('Error', 'nano-vt')
            ]
        ]);
    }

    // 5. Render Admin
    public function render_admin_page()
    {
        if (! current_user_can('manage_options')) {
            return;
        }
        $options = get_option($this->option_name);
?>
        <div class="wrap nano-wrap">
            <h1>🛡️ <?php esc_html_e('Nano VT Scanner', 'nano-vt'); ?></h1>

            <form method="post" action="options.php" class="nano-card">
                <?php settings_fields('nano_vt_group'); ?>
                <div class="nano-api-row">
                    <label for="nano_api_key">🔑 API Key</label>
                    <input type="password" id="nano_api_key" name="nano_vt_settings[api_key]"
                        value="<?php echo esc_attr($options['api_key'] ?? ''); ?>"
                        class="regular-text" placeholder="VT API Key">
                    <?php submit_button(__('Verify & Save', 'nano-vt'), 'primary', 'submit', false); ?>
                </div>
            </form>

            <div class="nano-dashboard">
                <div class="nano-controls">
                    <input type="text" id="nano_target" placeholder="<?php esc_attr_e('IP / Domain / URL', 'nano-vt'); ?>">
                    <button class="button button-primary" id="nano_scan_btn"><?php esc_html_e('Scan', 'nano-vt'); ?></button>
                    <div class="nano-actions">
                        <a href="#" id="nano_shodan_btn" target="_blank" class="button" title="Shodan" style="display:none;">🕵️</a>
                        <button id="nano_copy_btn" class="button" title="Copy" style="display:none;">📋</button>
                    </div>
                </div>

                <div class="nano-grid">
                    <div class="nano-result" id="nano_result_panel">
                        <p class="nano-placeholder"><?php esc_html_e('Ready to engage.', 'nano-vt'); ?></p>
                    </div>
                    <div class="nano-log" id="nano_debug_log">
                        <div class="log-header">Debug Log</div>
                        <pre id="nano_log_content"></pre>
                    </div>
                </div>
            </div>
        </div>
<?php
    }
}

new Nano_VT_Scanner();
