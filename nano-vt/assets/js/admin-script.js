jQuery(document).ready(function ($) {
    function log(msg) {
        var time = new Date().toLocaleTimeString();
        $('#nano_log_content').append('[' + time + '] ' + msg + '\n');
        var logDiv = $('#nano_debug_log');
        logDiv.scrollTop(logDiv[0].scrollHeight);
    }

    log('System initialized. Ready.');

    $('#nano_scan_btn').on('click', function (e) {
        e.preventDefault();
        var target = $('#nano_target').val().trim();

        if (!target) {
            alert('Please enter a target.');
            return;
        }

        $('#nano_result_panel').html('⏳ ' + nanoVars.i18n.scanning);
        log('Initiating scan for: ' + target);
        $('#nano_shodan_btn, #nano_copy_btn').hide();

        $.ajax({
            url: nanoVars.api_url,
            method: 'GET',
            beforeSend: function (xhr) {
                xhr.setRequestHeader('X-WP-Nonce', nanoVars.nonce);
            },
            data: { target: target },
            success: function (res) {
                log('Response received. Status: 200 OK');
                var stats = res.last_analysis_stats;
                var type = res._tiny_type;
                var clean = res._tiny_target_clean;

                var typeIcon = '❓';
                if (type === 'ip') typeIcon = '🌐';
                if (type === 'domain') typeIcon = '🏰';
                if (type === 'url') typeIcon = '🔗';

                var html = '<h3>' + nanoVars.i18n.report + '</h3>';
                html += '<div><strong>Type:</strong> ' + typeIcon + ' ' + type.toUpperCase() + '</div>';
                html += '<div><strong>Target:</strong> ' + clean + '</div>';
                html += '<hr>';
                html += '<div style="color:red">🔴 Malicious: ' + stats.malicious + '</div>';
                html += '<div style="color:orange">🟠 Suspicious: ' + stats.suspicious + '</div>';
                html += '<div style="color:green">🟢 Harmless: ' + stats.harmless + '</div>';
                html += '<div style="color:gray">⚪ Undetected: ' + stats.undetected + '</div>';
                html += '<hr>';
                html += '<div>Timeout: ' + (stats.timeout || 0) + '</div>';
                html += '<div>Failure: ' + (stats.failure || 0) + '</div>';

                $('#nano_result_panel').html(html);

                // update shodan
                var shodanUrl = 'https://www.shodan.io/search?query=' + encodeURIComponent(clean);
                $('#nano_shodan_btn').attr('href', shodanUrl).show();

                // update copy
                $('#nano_copy_btn').data('clip', clean).show();
            },
            error: function (xhr) {
                var err = xhr.responseJSON ? xhr.responseJSON.message : xhr.statusText;
                log('Error: ' + err);
                $('#nano_result_panel').html('❌ ' + err);
            }
        });
    });

    $('#nano_copy_btn').on('click', function (e) {
        e.preventDefault();
        var txt = $(this).data('clip');
        navigator.clipboard.writeText(txt).then(function () {
            log('Copied to clipboard: ' + txt);
            alert('Copied!');
        });
    });
});
