jQuery(document).ready(function ($) {
    // 📝 Helper function to write logs
    function tinyLog(msg) {
        var now = new Date().toISOString().split('T')[1].split('.')[0];
        var line = '[' + now + '] ' + msg + '\n';
        var $log = $('#tiny_debug_log');
        $log.val($log.val() + line);
        $log.scrollTop($log[0].scrollHeight); // Auto-scroll to bottom
    }

    $('#tiny_start_scan').on('click', function (e) {
        e.preventDefault();
        var target = $('#tiny_target').val().trim();

        // Clear previous logs and results
        $('#tiny_debug_log').val('');
        $('#tiny_scan_result').html('<strong>⏳ ' + tinyVtVars.scanning_msg + '</strong>'); // Use localized string
        $('#tiny_actions').hide(); // Hide actions during scan

        tinyLog('🚀 Starting scan process...');
        tinyLog('🎯 Input Target: "' + target + '"');

        if (!target) {
            tinyLog('❌ Error: Target is empty.');
            alert(tinyVtVars.empty_target_msg); // Use localized string
            return;
        }

        // $('#tiny_scan_result').show().html(...); // 🗑️ 移到上面去做
        tinyLog('📡 Preparing to send AJAX request...');

        $.ajax({
            url: tinyVtVars.rest_url, // Use localized REST URL
            method: 'POST',
            beforeSend: function (xhr) {
                xhr.setRequestHeader('X-WP-Nonce', tinyVtVars.nonce); // Use localized Nonce
                tinyLog('🔐 Nonce set. Sending request to ' + tinyVtVars.rest_url);
            },
            data: {
                target: target
            },
            success: function (res) {
                tinyLog('✅ Response received (200 OK).');
                tinyLog('📦 Data: ' + JSON.stringify(res, null, 2));

                // REST API 直接回傳資料
                var stats = res.last_analysis_stats;
                var type = res._tiny_type || 'unknown';
                var cleanTarget = res._tiny_target_clean || target;

                // 🎨 UI Icons based on type
                var typeIcon = '❓';
                var typeLabel = 'Unknown';
                if (type === 'ip') { typeIcon = '🌐'; typeLabel = 'IP Address'; }
                if (type === 'domain') { typeIcon = '🏰'; typeLabel = 'Domain'; }
                if (type === 'url') { typeIcon = '🔗'; typeLabel = 'URL'; }

                var output = "### " + tinyVtVars.scan_report_msg + " ###\n";
                output += "📌 [" + typeIcon + " " + typeLabel + "] " + cleanTarget + "\n";
                output += "--------------------------------\n";
                output += "🔴 " + tinyVtVars.malicious_msg + ": " + stats.malicious + "\n";
                output += "🟠 " + tinyVtVars.suspicious_msg + ": " + stats.suspicious + "\n";
                output += "🟢 " + tinyVtVars.harmless_msg + ": " + stats.harmless + "\n";
                output += "⚪ " + tinyVtVars.undetected_msg + ": " + stats.undetected + "\n";
                output += "--------------------------------\n";

                // 🕵️ 顯示隱藏版數據 (Full 8 Types)
                output += "⏳ " + tinyVtVars.timeout_msg + ": " + (stats.timeout || 0) + "\n";
                output += "🐢 " + tinyVtVars.confirmed_timeout_msg + ": " + (stats['confirmed-timeout'] || 0) + "\n";
                output += "🛑 " + tinyVtVars.failure_msg + ": " + (stats.failure || 0) + "\n";
                output += "🚫 " + tinyVtVars.type_unsupported_msg + ": " + (stats['type-unsupported'] || 0) + "\n\n";

                output += tinyVtVars.synced_msg;
                $('#tiny_scan_result').text(output);

                // 🔗 Update Smart Actions
                // Shodan only works well for IPs, but we can search domains too. URLs not so much.
                var shodanUrl = 'https://www.shodan.io/search?query=' + encodeURIComponent(cleanTarget);
                // If URL, Shodan search might not be useful, maybe disable or change to domain? 
                // For simplified UX, we just search whatever the clean target is.

                $('#tiny_btn_shodan').attr('href', shodanUrl);
                $('#tiny_actions').css('display', 'flex'); // Show buttons

                // 📋 Copy Feature
                $('#tiny_btn_copy').off('click').on('click', function (e) {
                    e.preventDefault();
                    navigator.clipboard.writeText(target).then(function () {
                        tinyLog('📋 Target copied to clipboard.');
                        var originalText = $('#tiny_btn_copy').text();
                        $('#tiny_btn_copy').text('✅ Copied!');
                        setTimeout(function () {
                            $('#tiny_btn_copy').text(originalText);
                        }, 2000);
                    });
                });

                tinyLog('🎉 Process completed successfully.');
            },
            error: function (xhr, status, error) {
                tinyLog('❌ AJAX Error: ' + status);
                tinyLog('🛑 Error Details: ' + error);

                var msg = tinyVtVars.unknown_error_msg;
                if (xhr.responseJSON) {
                    tinyLog('📄 Response JSON: ' + JSON.stringify(xhr.responseJSON));
                    msg = xhr.responseJSON.message || xhr.responseJSON.code;
                } else {
                    tinyLog('📄 Response Text: ' + xhr.responseText);
                }

                $('#tiny_scan_result').html('<span style="color:#d63638;">❌ ' + tinyVtVars.scan_failed_msg + ': ' + msg + '</span>');
            }
        });
    });
});
