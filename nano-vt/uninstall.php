<?php
// If uninstall not called from WordPress, then exit.
if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete options
delete_option('nano_vt_settings');

// Delete transients
// Note: We can't delete dynamic transients easily without knowing the keys, 
// but in a production environment we might use a prefix query if supported or specific keys.
// For now, the main settings deletion is the critical cleanup.
