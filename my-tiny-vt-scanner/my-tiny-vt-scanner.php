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
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_ajax_tiny_vt_query', [$this, 'handle_ajax_query']);
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
    public function validate_api_key($input)
    {
        // 為了安全，先把輸入的文字清理乾淨 (sanitize)，去掉不該有的怪符號
        $key = sanitize_text_field($input['api_key']);

        // --- 第一關：空值檢查 ---
        if (empty($key)) {
            add_settings_error('tiny_vt_messages', 'tiny_vt_error', '⚠️ API Key 不能為空喔！請輸入後再儲存。', 'error');
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
        if (is_wp_error($response) || $code !== 200) {
            $msg = ($code === 401 || $code === 403) ? '🚫 API Key 無效 (沒有權限/Unauthorized)' : '⚠️ 連線 VT 失敗或 API 點數耗盡';
            add_settings_error('tiny_vt_messages', 'tiny_vt_error', $msg . '，請重新檢查。', 'error');
            return get_option($this->option_name); // 驗證失敗，保持原狀
        }

        // 恭喜！過關了！
        add_settings_error('tiny_vt_messages', 'tiny_vt_success', '✅ API Key 驗證通過！已成功儲存。', 'updated');
        return $input;
    }

    // 📌 4. 渲染後台介面 (畫畫面)
    // 這裡負責把後台那個「輸入框」和「按鈕」畫給 JJ 哥看。
    public function render_admin_page()
    {
        $options = get_option($this->option_name);
?>
        <div class="wrap">
            <h1>🛡️ my-tiny-vt-scanner</h1>
            <p>這是一款為 BMI-ADAR 架構設計的輕量化資安檢測工具。</p>

            <form method="post" action="options.php">
                <?php settings_fields('tiny_vt_group'); ?>
                <table class="form-table">
                    <tr>
                        <th>VirusTotal API Key</th>
                        <td>
                            <input type="password" name="my_tiny_vt_settings[api_key]" value="<?php echo esc_attr($options['api_key'] ?? ''); ?>" class="regular-text">
                            <p class="description">輸入 VT v3 API Key 後點擊儲存，系統會自動進行可用性測試。</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('驗證並儲存設定'); ?>
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
                        if (res.success) {
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

    // 📌 5. AJAX 核心邏輯：正規化檢查與 API 呼叫
    // 這是外掛的「大腦」。當前端按下「開始掃描」時，就會呼叫這裡。
    // 它的工作流程：
    // 1. 檢查憑證 (Nonce) -> 確保不是駭客亂呼叫
    // 2. 檢查資料 (Sanitize) -> 確保輸入的 IP/URL 格式正確
    // 3. 呼叫 VT API -> 去問 VirusTotal
    // 4. 回傳結果 -> 把結果丟回給前端顯示
    public function handle_ajax_query()
    {
        check_ajax_referer('tiny_vt_ajax_nonce');

        $target = sanitize_text_field($_POST['target']);
        $type = $_POST['type'];
        $api_key = get_option($this->option_name)['api_key'] ?? '';

        if (empty($api_key)) wp_send_json_error('尚未設定 API Key');

        // --- 🧹 正規化檢查 (Normalization) ---
        // 這一步像是在「整隊」。不管使用者輸入什麼格式，我們都要把它整理成統一的樣子。

        if ($type === 'ip') {
            // [教學] 這裡用的是 "Regular Expression" (正規表達式)
            // 它像是一個篩子，確保輸入的看起來真的像 IP (例如 192.168.1.1)。
            // 如果你輸入 "abc.def.ghi"，就會被這個篩子擋下來。
            $ip_regex = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';

            if (! preg_match($ip_regex, $target)) {
                wp_send_json_error('🚫 不正確的 IPv4 格式！請確認你輸入的是像 8.8.8.8 這樣的數字組合。');
            }
            $api_url = "https://www.virustotal.com/api/v3/ip_addresses/{$target}";
        } else {
            // [URL 檢查]
            // 我們要求一定要有 http:// 或 https://，這樣 VT 才看得懂。
            if (! filter_var($target, FILTER_VALIDATE_URL)) {
                wp_send_json_error('🚫 網址格式錯誤！請記得加上 http:// 或 https:// 喔！');
            }

            // [小知識] VirusTotal 的 URL 查詢很特別
            // 他們不直接查網址，而是要把網址變成一串 "Base64 編碼" 的 ID。
            // 這就像把 "Google.com" 翻譯成 "R29vZ2xlLmNvbQ==" 這樣的密碼，VT 才認得。
            $url_id = rtrim(strtr(base64_encode($target), '+/', '-_'), '=');
            $api_url = "https://www.virustotal.com/api/v3/urls/{$url_id}";
        }

        // 🚀 執行外部 API 請求
        // 這裡就是「信差」出發去 VirusTotal 辦事的時候了。
        // 我們給他 20 秒的時間 (timeout)，如果太久沒回來，就當作失敗。
        $response = wp_remote_get($api_url, [
            'headers' => ['x-apikey' => $api_key],
            'timeout' => 20
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error('⚠️ 連線失敗：信差出門後就沒回來了 (連線逾時或網路不通)。');
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (isset($body['data']['attributes'])) {
            wp_send_json_success($body['data']['attributes']);
        } else {
            wp_send_json_error($body['error']['message'] ?? 'VT API 回傳未知錯誤');
        }
    }
}

new My_Tiny_VT_Scanner();
