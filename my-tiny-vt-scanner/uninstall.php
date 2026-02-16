<?php

/**
 * Fired when the plugin is uninstalled.
 *
 * @package My_Tiny_VT_Scanner
 */

// If uninstall not called from WordPress, then exit.
if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// 1. Delete option
delete_option('my_tiny_vt_settings');

// 2. Clear all transients related to this plugin
// Note: Normally transients are specific, but since we use md5(target) as suffix,
// we can't delete them all easily unless we query DB.
// For a simple plugin, we can skip complex DB query or just leave them to expire.
// However, if we want to be thorough:
global $wpdb;
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_tiny_vt_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_tiny_vt_%'");
