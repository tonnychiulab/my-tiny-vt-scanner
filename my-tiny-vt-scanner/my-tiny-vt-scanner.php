<?php

/**
 * Plugin Name: my-tiny-vt-scanner
 * Description: 輕量級 VirusTotal API v3 整合工具，支援 IP 與 URL 風險掃描與正規化驗證。
 * Version: 1.1
 * Author: BMI Security Team
 */

if (! defined('ABSPATH')) exit;

class My_Tiny_VT_Scanner
{

    private $option_name = 'my_tiny_vt_settings';

    public function __construct()
    {
        // 🌍 載入多國語系支援
        add_action('plugins_loaded', [$this, 'load_textdomain']);

        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        // 🗑️ [移除] 我們不再用舊的 admin-ajax 了
        // add_action('wp_ajax_tiny_vt_query', [$this, 'handle_ajax_query']);

        // ✨ [新增] 改用現代化的 REST API
        // 告訴 WordPress：「我們有新的 API 路徑要註冊喔！」
        add_action('rest_api_init', [$this, 'register_rest_routes']);
    }

    // 📌 0-1. 載入翻譯檔
    public function load_textdomain()
    {
        load_plugin_textdomain('my-tiny-vt-scanner', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }

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
        add_menu_page('My Tiny VT', 'My Tiny VT', 'manage_options', 'my-tiny-vt-scanner', [$this, 'render_admin_page'], 'dashicons-shield-alt');
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
            <h1>🛡️ <?php _e('My Tiny VT Scanner', 'my-tiny-vt-scanner'); ?></h1>
            <p><?php _e('A lightweight VirusTotal API v3 integration tool for BMI-ADAR architecture.', 'my-tiny-vt-scanner'); ?></p>

            <form method="post" action="options.php">
                <?php settings_fields('tiny_vt_group'); ?>
                <table class="form-table">
                    <tr>
                        <th><?php _e('VirusTotal API Key', 'my-tiny-vt-scanner'); ?></th>
                        <td>
                            <input type="password" name="my_tiny_vt_settings[api_key]" value="<?php echo esc_attr($options['api_key'] ?? ''); ?>" class="regular-text">
                            <p class="description"><?php _e('Enter your VT v3 API Key and save. The system will automatically verify it.', 'my-tiny-vt-scanner'); ?></p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(__('Verify & Save Settings', 'my-tiny-vt-scanner')); ?>
            </form>

            <hr style="margin:30px 0;">

            <div class="tiny-query-container" style="background:#fff; border:1px solid #ccd0d4; padding:20px; max-width:800px;">
                <h2>🔍 <?php _e('Real-time Risk Scanner', 'my-tiny-vt-scanner'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php _e('Scan Type', 'my-tiny-vt-scanner'); ?></th>
                        <td>
                            <select id="tiny_type">
                                <option value="ip"><?php _e('IPv4 Address', 'my-tiny-vt-scanner'); ?></option>
                                <option value="url"><?php _e('URL', 'my-tiny-vt-scanner'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e('Target', 'my-tiny-vt-scanner'); ?></th>
                        <td>
                            <input type="text" id="tiny_target" class="large-text" placeholder="<?php esc_attr_e('e.g., 1.2.3.4 or https://malicious-site.com', 'my-tiny-vt-scanner'); ?>">
                        </td>
                    </tr>
                </table>
                <p>
                    <button class="button button-primary" id="tiny_start_scan"><?php _e('Start Normalized Scan', 'my-tiny-vt-scanner'); ?></button>
                </p>
                <div id="tiny_scan_result" style="margin-top:20px; padding:15px; background:#f6f7f7; border-left:4px solid #2271b1; display:none; white-space:pre-wrap; font-family:monospace;"></div>
            </div>
        </div>

        <script>
            jQuery(document).ready(function($) {
                $('#tiny_start_scan').on('click', function(e) {
                    e.preventDefault();
                    var target = $('#tiny_target').val();
                    var type = $('#tiny_type').val();

                    $('#tiny_scan_result').show().html('<strong>⏳ ' + '<?php _e("Scanning and analyzing...", "my-tiny-vt-scanner"); ?>' + '</strong>');

                    $.ajax({
                        url: '/wp-json/tiny-vt/v1/scan',
                        method: 'POST',
                        beforeSend: function(xhr) {
                            xhr.setRequestHeader('X-WP-Nonce', '<?php echo wp_create_nonce("wp_rest"); ?>');
                        },
                        data: {
                            target: target,
                            type: type
                        },
                        success: function(res) {
                            // REST API 直接回傳資料，不需要像 AJAX 那樣判斷 res.success
                            var stats = res.last_analysis_stats;
                            var output = "### " + '<?php _e("Scan Report", "my-tiny-vt-scanner"); ?>' + " ###\n";
                            output += "📌 " + '<?php _e("Target", "my-tiny-vt-scanner"); ?>' + ": " + target + "\n";
                            output += "🔴 " + '<?php _e("Malicious", "my-tiny-vt-scanner"); ?>' + ": " + stats.malicious + "\n";
                            output += "🟠 " + '<?php _e("Suspicious", "my-tiny-vt-scanner"); ?>' + ": " + stats.suspicious + "\n";
                            output += "🟢 " + '<?php _e("Harmless", "my-tiny-vt-scanner"); ?>' + ": " + stats.harmless + "\n";
                            output += "⚪ " + '<?php _e("Undetected", "my-tiny-vt-scanner"); ?>' + ": " + stats.undetected + "\n\n";
                            output += '<?php _e("Detailed results synced to BMI logs.", "my-tiny-vt-scanner"); ?>';
                            $('#tiny_scan_result').text(output);
                        },
                        error: function(xhr) {
                            // 處理錯誤 (例如 401 沒權限, 400 格式錯誤)
                            var msg = xhr.responseJSON ? xhr.responseJSON.message : '<?php _e("Unknown Error", "my-tiny-vt-scanner"); ?>';
                            $('#tiny_scan_result').html('<span style="color:#d63638;">❌ ' + '<?php _e("Scan Failed", "my-tiny-vt-scanner"); ?>' + ': ' + msg + '</span>');
                        }
                    });
                });
            });
        </script>
<?php
    }

    // 📌 5. REST API 核心邏輯 (取代舊的 AJAX)
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
        $type   = sanitize_text_field($request->get_param('type'));

        $options = get_option($this->option_name);
        $api_key = $options['api_key'] ?? '';

        if (empty($api_key)) {
            return new \WP_Error('no_api_key', __('API Key not set.', 'my-tiny-vt-scanner'), ['status' => 400]);
        }

        // --- 🧹 正規化檢查 (Normalization) ---
        if ($type === 'ip') {
            $ip_regex = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';
            if (! preg_match($ip_regex, $target)) {
                return new \WP_Error('invalid_ip', __('Invalid IPv4 format.', 'my-tiny-vt-scanner'), ['status' => 400]);
            }
            $api_url = "https://www.virustotal.com/api/v3/ip_addresses/{$target}";
        } else {
            if (! filter_var($target, FILTER_VALIDATE_URL)) {
                return new \WP_Error('invalid_url', __('Invalid URL format. Please include http:// or https://', 'my-tiny-vt-scanner'), ['status' => 400]);
            }
            $url_id = rtrim(strtr(base64_encode($target), '+/', '-_'), '=');
            $api_url = "https://www.virustotal.com/api/v3/urls/{$url_id}";
        }

        // --- ⚡ 快取機制 (Caching) ---
        // 我們用 "transient" (暫存) 來記住結果。
        // Key 的名字要是唯一的，所以我們把 target 加進去。
        $cache_key = 'tiny_vt_' . md5($target);
        $cached_data = get_transient($cache_key);

        if ($cached_data) {
            // [省錢] 找到了！直接回傳，不用花 API 點數。
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

            // [存檔] 把結果記下來，保存 1 小時 (3600 秒)
            set_transient($cache_key, $data, 3600);

            return rest_ensure_response($data);
        } else {
            return new \WP_Error('vt_error', $body['error']['message'] ?? __('Unknown API Error', 'my-tiny-vt-scanner'), ['status' => 400]);
        }
    }
}

new My_Tiny_VT_Scanner();
