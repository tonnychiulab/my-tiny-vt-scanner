<?php

/**
 * Plugin Name: My Tiny VT Scanner
 * Description: 輕量級 VirusTotal API v3 整合工具，支援 IP 與 URL 風險掃描與正規化驗證。
 * Version: 1.1
 * Author: BMI Security Team
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.9
 * Requires PHP: 8.3
 */

if (! defined('ABSPATH')) exit;

class My_Tiny_VT_Scanner
{

    private $option_name = 'my_tiny_vt_settings';

    public function __construct()
    {
        // 🌍 載入多國語系支援
        // Note: WordPress 4.6+ automatically loads translations from the 'languages' directory
        // if the text domain matches the plugin slug.
        // add_action('plugins_loaded', [$this, 'load_textdomain']);

        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        // 🗑️ [移除] 我們不再用舊的 admin-ajax 了
        // add_action('wp_ajax_tiny_vt_query', [$this, 'handle_ajax_query']);

        // ✨ [新增] 改用現代化的 REST API
        // 告訴 WordPress：「我們有新的 API 路徑要註冊喔！」
        add_action('rest_api_init', [$this, 'register_rest_routes']);
    }

    // 📌 0-1. 載入翻譯檔 (Deprecated since WP 4.6 if using standard path)
    // public function load_textdomain()
    // {
    //     load_plugin_textdomain('my-tiny-vt-scanner', false, dirname(plugin_basename(__FILE__)) . '/languages');
    // }

    // 📌 0. 註冊 REST API 路徑
    // 這裡定義了我們的「新窗口」。
    // 網址會變成：/wp-json/tiny-vt/v1/scan
    public function register_rest_routes()
    {
        register_rest_route('tiny-vt/v1', '/scan', [
            'methods'             => 'POST', // 只接受 POST 請求 (像寄掛號信)
            'callback'            => [$this, 'handle_rest_query'], // 收到信後，交給 handle_rest_query 處理
            'permission_callback' => function () {
                // 🔒 安全檢查：只有管理員才能用！
                return current_user_can('manage_options');
            },
        ]);
    }

    // 📌 1. 建立後台選單
    // 這一步是為了讓 JJ 哥在 WordPress 的左側黑色選單裡，找到我們的外掛入口。
    public function add_admin_menu()
    {
        add_menu_page(
            __('My Tiny VT Scanner', 'my-tiny-vt-scanner'),
            __('My Tiny VT Scanner', 'my-tiny-vt-scanner'),
            'manage_options',
            'my-tiny-vt-scanner',
            [$this, 'render_admin_page'],
            'dashicons-shield',
            99
        );
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
    }

    // 📌 1.5 Enqueue Scripts and Styles
    public function enqueue_admin_assets($hook)
    {
        if ($hook !== 'toplevel_page_my-tiny-vt-scanner') {
            return;
        }

        wp_enqueue_style('my-tiny-vt-admin-css', plugin_dir_url(__FILE__) . 'assets/css/admin-style.css', [], '1.1');
        wp_enqueue_script('my-tiny-vt-admin-js', plugin_dir_url(__FILE__) . 'assets/js/admin-script.js', ['jquery'], '1.1', true);

        wp_localize_script('my-tiny-vt-admin-js', 'tinyVtVars', [
            'rest_url' => rest_url('tiny-vt/v1/scan'),
            'nonce' => wp_create_nonce('wp_rest'),
            'scanning_msg' => __('Scanning and analyzing...', 'my-tiny-vt-scanner'),
            'empty_target_msg' => __('Please enter a target!', 'my-tiny-vt-scanner'),
            'scan_report_msg' => __('Scan Report', 'my-tiny-vt-scanner'),
            'target_msg' => __('Target', 'my-tiny-vt-scanner'),
            'malicious_msg' => __('Malicious', 'my-tiny-vt-scanner'),
            'suspicious_msg' => __('Suspicious', 'my-tiny-vt-scanner'),
            'harmless_msg' => __('Harmless', 'my-tiny-vt-scanner'),
            'undetected_msg' => __('Undetected', 'my-tiny-vt-scanner'),
            'timeout_msg' => __('Timeout', 'my-tiny-vt-scanner'),
            'confirmed_timeout_msg' => __('Confirmed Timeout', 'my-tiny-vt-scanner'),
            'failure_msg' => __('Failure', 'my-tiny-vt-scanner'),
            'type_unsupported_msg' => __('Type Unsupported', 'my-tiny-vt-scanner'),
            'synced_msg' => __('Detailed results synced to BMI logs.', 'my-tiny-vt-scanner'),
            'unknown_error_msg' => __('Unknown Error', 'my-tiny-vt-scanner'),
            'scan_failed_msg' => __('Scan Failed', 'my-tiny-vt-scanner')
        ]);
    }

    // 📌 2. 註冊設定項與驗證邏輯
    // 這裡我們告訴 WordPress：「嘿，我要存一個設定叫做 my_tiny_vt_settings」。
    // 並且我們設了一個「守門員」 (validate_api_key)，在儲存之前先檢查一下資料對不對。
    public function register_settings()
    {
        register_setting('tiny_vt_group', $this->option_name, [
            'sanitize_callback' => [$this, 'validate_api_key']
        ]);
    }

    // 📌 3. 儲存前強制驗證 API KEY 的有效性
    // 這個函數就是我們的「守門員」。
    // 當 JJ 哥按下儲存時，我們不會馬上存進去，而是先做兩件事：
    // 1. 檢查是不是空的？ (如果是空的就報錯)
    // 2. 真的拿去 VirusTotal 試用看看！ (確保這把鑰匙真的能開門)
    // [教學] 加上 array 型別宣告，讓程式更嚴謹
    public function validate_api_key(array $input): array
    {
        // 為了安全，先把輸入的文字清理乾淨 (sanitize)，去掉不該有的怪符號
        $key = sanitize_text_field($input['api_key']);

        // --- 第一關：空值檢查 ---
        if (empty($key)) {
            // [i18n] __('文字', 'domain') 是翻譯函式。
            add_settings_error('tiny_vt_messages', 'tiny_vt_error', __('API Key cannot be empty!', 'my-tiny-vt-scanner'), 'error');
            return get_option($this->option_name); // 驗證失敗，回傳舊的設定 (不讓錯誤的覆蓋)
        }

        // --- 第二關：實地測試 ---
        // 我們試著用這把 Key 去查一個大家都知道的 IP (Google 的 8.8.8.8)
        // 如果能查到，表示 Key 是好的；如果查不到，表示 Key 有問題。
        $response = wp_remote_get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', [
            'headers' => ['x-apikey' => $key],
            'timeout' => 10
        ]);

        $code = wp_remote_retrieve_response_code($response);

        // 如果回應代碼不是 200 (成功)，那就代表出錯了
        // 如果回應代碼不是 200 (成功)，那就代表出錯了
        if (is_wp_error($response) || $code !== 200) {
            $msg = ($code === 401 || $code === 403)
                ? __('Invalid API Key (Unauthorized).', 'my-tiny-vt-scanner')
                : __('Failed to connect to VirusTotal or quota exceeded.', 'my-tiny-vt-scanner');

            add_settings_error('tiny_vt_messages', 'tiny_vt_error', $msg, 'error');
            return get_option($this->option_name); // 驗證失敗，保持原狀
        }

        // 恭喜！過關了！
        add_settings_error('tiny_vt_messages', 'tiny_vt_success', __('API Key verified successfully!', 'my-tiny-vt-scanner'), 'updated');
        return $input;
    }

    // 📌 4. 渲染後台介面 (畫畫面)
    // 這裡負責把後台那個「輸入框」和「按鈕」畫給 JJ 哥看。
    public function render_admin_page()
    {
        $options = get_option($this->option_name);
?>
        <div class="wrap">
            <h1>🛡️ <?php esc_html_e('My Tiny VT Scanner', 'my-tiny-vt-scanner'); ?></h1>
            <p><?php esc_html_e('A lightweight VirusTotal API v3 integration tool for BMI-ADAR architecture.', 'my-tiny-vt-scanner'); ?></p>

            <form method="post" action="options.php" class="tiny-api-form">
                <?php settings_fields('tiny_vt_group'); ?>
                <div class="tiny-api-container">
                    <label for="tiny_api_key" class="tiny-api-label">🔑 <?php esc_html_e('VirusTotal API Key', 'my-tiny-vt-scanner'); ?></label>
                    <div class="tiny-api-wrapper">
                        <input type="password" id="tiny_api_key" name="my_tiny_vt_settings[api_key]" value="<?php echo esc_attr($options['api_key'] ?? ''); ?>" class="regular-text" placeholder="Enter your VT API Key">
                        <?php submit_button(__('Verify & Save', 'my-tiny-vt-scanner'), 'primary', 'submit', false, ['title' => __('Validate Key with VT and save settings', 'my-tiny-vt-scanner')]); ?>
                    </div>
                    <p class="description"><?php esc_html_e('Enter your VT v3 API Key and save. The system will automatically verify it.', 'my-tiny-vt-scanner'); ?></p>
                </div>
            </form>

            <hr style="margin:30px 0;">

            <div class="tiny-query-container">
                <div class="tiny-controls">
                    <h2 style="margin:0; padding:0; font-size:1.2em;">🔍 <?php esc_html_e('Scanner', 'my-tiny-vt-scanner'); ?></h2>
                    <div class="tiny-input-group">
                        <input type="text" id="tiny_target" placeholder="<?php esc_attr_e('Enter IP or URL (e.g., 8.8.8.8)', 'my-tiny-vt-scanner'); ?>">
                        <button class="button button-primary" id="tiny_start_scan" title="<?php esc_attr_e('Start VirusTotal analysis', 'my-tiny-vt-scanner'); ?>"><?php esc_html_e('Scan Now', 'my-tiny-vt-scanner'); ?></button>

                        <!-- 🛠️ Smart Actions (Hidden initially) -->
                        <span id="tiny_actions" style="display:none; gap:5px;">
                            <a href="#" id="tiny_btn_shodan" target="_blank" class="button" title="<?php esc_attr_e('Search on Shodan (Opens in a new tab)', 'my-tiny-vt-scanner'); ?>">🕵️ Shodan <span class="dashicons dashicons-external" style="font-size:14px; line-height:26px; vertical-align:middle;"></span></a>
                            <button id="tiny_btn_copy" class="button" title="<?php esc_attr_e('Copy target to clipboard', 'my-tiny-vt-scanner'); ?>">📋 Copy</button>
                        </span>
                    </div>
                </div>
                <p class="description" style="margin-top:5px; margin-bottom:0; color:#666; font-size:12px;">
                    <?php esc_html_e('Auto-detects IP/URL. Results & logs appear below.', 'my-tiny-vt-scanner'); ?>
                </p>

                <!-- 📊 Dashboard Grid Layout -->
                <div class="tiny-dashboard-grid">
                    <!-- Left: Scan Result -->
                    <div class="tiny-col-main">
                        <div id="tiny_scan_result" class="tiny-card result-card">
                            <p style="color:#666; font-style:italic; border:none; padding:0; margin:0;"><?php esc_html_e('Ready to scan...', 'my-tiny-vt-scanner'); ?></p>
                        </div>
                    </div>

                    <!-- Right: Debug Log -->
                    <div class="tiny-col-log">
                        <textarea id="tiny_debug_log" readonly placeholder="Debug logs..."></textarea>
                    </div>
                </div>
            </div>
        </div>
<?php
    }

    //  5. REST API 核心邏輯 (取代舊的 AJAX)
    // 這是外掛的新「大腦」。
    // 它的工作流程：
    // 1. 檢查資料 (Sanitize) 
    // 2. ⚡ 查快取！(如果剛查過，直接給答案，不用跑去 VT)
    // 3. 呼叫 VT API (如果沒快取)
    // 4. 存快取！(把答案記下來，下次用)
    // 5. 回傳結果
    public function handle_rest_query(\WP_REST_Request $request)
    {
        $target = sanitize_text_field($request->get_param('target'));
        // $type = ... 🗑️ [移除] 不再需要前端告訴我們是什麼

        $options = get_option($this->option_name);
        $api_key = $options['api_key'] ?? '';

        if (empty($api_key)) {
            return new \WP_Error('no_api_key', __('API Key not set.', 'my-tiny-vt-scanner'), ['status' => 400]);
        }

        // --- 💡 智慧判斷 (Smart Detection) ---
        // 判斷順序：IP -> Domain -> URL

        $type = 'unknown';
        $api_url = '';
        $clean_target = $target; // 用於顯示或進一步處理

        // IP Regex
        $ip_regex = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';

        if (preg_match($ip_regex, $target)) {
            // 1. IP
            $type = 'ip';
            $api_url = "https://www.virustotal.com/api/v3/ip_addresses/{$target}";
        } else {
            // 先嘗試清理 protocol
            $clean_target = preg_replace('#^https?://#', '', $target);
            $clean_target = rtrim($clean_target, '/'); // 移除結尾斜線

            // 判斷是不是單純的 Domain (沒有路徑，沒有 Query)
            // 簡單判斷：如果不包含 '/' 且看起來像 Domain
            if (strpos($clean_target, '/') === false) {
                // 2. Domain (e.g., google.com, sub.test.com)
                $type = 'domain';
                $api_url = "https://www.virustotal.com/api/v3/domains/{$clean_target}";
            } else {
                // 3. URL (e.g., google.com/foo, http://site.com)
                $type = 'url';

                // URL 必須要有 protocol，沒有就補上
                if (strpos($target, 'http') !== 0) {
                    $target = 'http://' . $target;
                }

                if (! filter_var($target, FILTER_VALIDATE_URL)) {
                    return new \WP_Error('invalid_target', __('Invalid format. Please enter a valid IP (8.8.8.8), Domain (example.com), or URL (http://example.com/foo).', 'my-tiny-vt-scanner'), ['status' => 400]);
                }

                $url_id = rtrim(strtr(base64_encode($target), '+/', '-_'), '=');
                $api_url = "https://www.virustotal.com/api/v3/urls/{$url_id}";
            }
        }

        // --- ⚡ 快取機制 (Caching) ---
        $cache_key = 'tiny_vt_' . md5($target . $type); // 加入 type 以防萬一
        $cached_data = get_transient($cache_key);

        if ($cached_data) {
            return rest_ensure_response($cached_data);
        }

        // --- 🚀 執行外部 API 請求 ---
        $response = wp_remote_get($api_url, [
            'headers' => ['x-apikey' => $api_key],
            'timeout' => 20
        ]);

        if (is_wp_error($response)) {
            return new \WP_Error('api_error', __('Connection Failed: ', 'my-tiny-vt-scanner') . $response->get_error_message(), ['status' => 500]);
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (isset($body['data']['attributes'])) {
            $data = $body['data']['attributes'];

            // 🏷️ 注入我們的類型標記 (Frontend 用)
            $data['_tiny_type'] = $type;
            $data['_tiny_target_clean'] = $clean_target;

            // [存檔] 把結果記下來，保存 1 小時 (3600 秒)
            set_transient($cache_key, $data, 3600);

            return rest_ensure_response($data);
        } else {
            return new \WP_Error('vt_error', $body['error']['message'] ?? __('Unknown API Error', 'my-tiny-vt-scanner'), ['status' => 400]);
        }
    }
}

new My_Tiny_VT_Scanner();
