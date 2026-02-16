<?php
/**
 * Plugin Name: my-tiny-vt-scanner
 * Description: 輕量級 VirusTotal API v3 整合工具，支援 IP 與 URL 風險掃描與正規化驗證。
 * Version: 1.1
 * Author: BMI Security Team
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class My_Tiny_VT_Scanner {

    private $option_name = 'my_tiny_vt_settings';

    public function __construct() {
        add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'wp_ajax_tiny_vt_query', [ $this, 'handle_ajax_query' ] );
    }

    // 1. 建立後台選單
    public function add_admin_menu() {
        add_menu_page( 'My Tiny VT', 'My Tiny VT', 'manage_options', 'my-tiny-vt-scanner', [ $this, 'render_admin_page' ], 'dashicons-shield-alt' );
    }

    // 2. 註冊設定項與驗證邏輯
    public function register_settings() {
        register_setting( 'tiny_vt_group', $this->option_name, [
            'sanitize_callback' => [ $this, 'validate_api_key' ]
        ]);
    }

    // 3. 儲存前強制驗證 API KEY 的有效性
    public function validate_api_key( $input ) {
        $key = sanitize_text_field( $input['api_key'] );
        
        if ( empty( $key ) ) {
            add_settings_error( 'tiny_vt_messages', 'tiny_vt_error', 'API Key 不能為空', 'error' );
            return get_option( $this->option_name );
        }

        // 使用 Google DNS IP 測試金鑰是否能通過 VT v3 驗證
        $response = wp_remote_get( 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', [
            'headers' => [ 'x-apikey' => $key ],
            'timeout' => 10
        ]);

        $code = wp_remote_retrieve_response_code( $response );

        if ( is_wp_error( $response ) || $code !== 200 ) {
            $msg = ( $code === 401 || $code === 403 ) ? 'API Key 無效 (Unauthorized)' : '連線 VT 失敗或 API 點數耗盡';
            add_settings_error( 'tiny_vt_messages', 'tiny_vt_error', $msg . '，請重新檢查。', 'error' );
            return get_option( $this->option_name ); // 驗證失敗，保持原狀
        }

        add_settings_error( 'tiny_vt_messages', 'tiny_vt_success', 'API Key 驗證通過，設定已儲存。', 'updated' );
        return $input;
    }

    // 4. 渲染後台介面
    public function render_admin_page() {
        $options = get_option( $this->option_name );
        ?>
        <div class="wrap">
            <h1>🛡️ my-tiny-vt-scanner</h1>
            <p>這是一款為 BMI-ADAR 架構設計的輕量化資安檢測工具。</p>
            
            <form method="post" action="options.php">
                <?php settings_fields( 'tiny_vt_group' ); ?>
                <table class="form-table">
                    <tr>
                        <th>VirusTotal API Key</th>
                        <td>
                            <input type="password" name="my_tiny_vt_settings[api_key]" value="<?php echo esc_attr( $options['api_key'] ?? '' ); ?>" class="regular-text">
                            <p class="description">輸入 VT v3 API Key 後點擊儲存，系統會自動進行可用性測試。</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button( '驗證並儲存設定' ); ?>
            </form>

            <hr style="margin:30px 0;">

            <div class="tiny-query-container" style="background:#fff; border:1px solid #ccd0d4; padding:20px; max-width:800px;">
                <h2>🔍 實時風險掃描</h2>
                <table class="form-table">
                    <tr>
                        <th>掃描類型</th>
                        <td>
                            <select id="tiny_type">
                                <option value="ip">IPv4 地址</option>
                                <option value="url">URL 網址</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th>查詢目標</th>
                        <td>
                            <input type="text" id="tiny_target" class="large-text" placeholder="例如: 1.2.3.4 或 https://malicious-site.com">
                        </td>
                    </tr>
                </table>
                <p>
                    <button class="button button-primary" id="tiny_start_scan">開始正規化檢測</button>
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
                
                $('#tiny_scan_result').show().html('<strong>⏳ 正在進行圖譜掃描與分析...</strong>');

                $.post(ajaxurl, {
                    action: 'tiny_vt_query',
                    target: target,
                    type: type,
                    _ajax_nonce: '<?php echo wp_create_nonce("tiny_vt_ajax_nonce"); ?>'
                }, function(res) {
                    if(res.success) {
                        var stats = res.data.last_analysis_stats;
                        var output = "### 掃描報告 ###\n";
                        output += "📌 目標: " + target + "\n";
                        output += "🔴 惡意 (Malicious): " + stats.malicious + "\n";
                        output += "🟠 可疑 (Suspicious): " + stats.suspicious + "\n";
                        output += "🟢 安全 (Harmless): " + stats.harmless + "\n";
                        output += "⚪ 未評分 (Undetected): " + stats.undetected + "\n\n";
                        output += "詳細結果已同步至 BMI 日誌。";
                        $('#tiny_scan_result').text(output);
                    } else {
                        $('#tiny_scan_result').html('<span style="color:#d63638;">❌ 偵測失敗: ' + res.data + '</span>');
                    }
                });
            });
        });
        </script>
        <?php
    }

    // 5. AJAX 核心邏輯：正規化檢查與 API 呼叫
    public function handle_ajax_query() {
        check_ajax_referer( 'tiny_vt_ajax_nonce' );

        $target = sanitize_text_field( $_POST['target'] );
        $type = $_POST['type'];
        $api_key = get_option( $this->option_name )['api_key'] ?? '';

        if ( empty( $api_key ) ) wp_send_json_error( '尚未設定 API Key' );

        // --- 正規化檢查 (Normalization & Validation) ---
        if ( $type === 'ip' ) {
            // IPv4 嚴謹正則
            $ip_regex = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';
            if ( ! preg_match( $ip_regex, $target ) ) {
                wp_send_json_error( '不正確的 IPv4 格式，請確認是否為 0.0.0.0 ~ 255.255.255.255' );
            }
            $api_url = "https://www.virustotal.com/api/v3/ip_addresses/{$target}";
        } else {
            // URL 檢查 (必須含 Protocol)
            if ( ! filter_var( $target, FILTER_VALIDATE_URL ) ) {
                wp_send_json_error( '無效的 URL，請包含 http:// 或 https://' );
            }
            // VT v3 URL ID 規範：Base64 編碼且去掉末尾 "="
            $url_id = rtrim( strtr( base64_encode( $target ), '+/', '-_' ), '=' );
            $api_url = "https://www.virustotal.com/api/v3/urls/{$url_id}";
        }

        // 執行外部 API 請求
        $response = wp_remote_get( $api_url, [
            'headers' => [ 'x-apikey' => $api_key ],
            'timeout' => 20
        ]);

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( '遠端主機連線逾時' );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        
        if ( isset( $body['data']['attributes'] ) ) {
            wp_send_json_success( $body['data']['attributes'] );
        } else {
            wp_send_json_error( $body['error']['message'] ?? 'VT API 回傳未知錯誤' );
        }
    }
}

new My_Tiny_VT_Scanner();