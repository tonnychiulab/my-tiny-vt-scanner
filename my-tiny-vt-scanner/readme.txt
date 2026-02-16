=== My Tiny VT Scanner ===
Contributors: tonnychiu
Tags: security, virustotal, scanner, ip, url
Requires at least: 6.9
Tested up to: 6.9
Stable tag: 1.1
Requires PHP: 8.3
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

A lightweight VirusTotal API v3 integration tool for BMI-ADAR architecture.

== Description ==

My Tiny VT Scanner is a robust, lightweight security tool designed for the BMI-ADAR architecture. It leverages the VirusTotal API v3 to scan IP addresses and URLs for potential threats directly from your WordPress dashboard.

**Key Features:**

*   **Smart Detection:** Automatically distinguishes between IP addresses and URLs.
*   **VirusTotal API v3:** Uses the latest standard for threat intelligence.
*   **Detailed Explanations:** Provides clear insights into scan results (Malicious, Suspicious, Harmless).
*   **Debug Logs:** Built-in "Black Box" logging for easy troubleshooting.
*   **Smart Actions:** One-click shortcuts to search on Shodan or copy targets.
*   **Compact UI:** A dashboard-style interface optimized for efficiency.

== Installation ==

1.  Upload the `my-tiny-vt-scanner` folder to the `/wp-content/plugins/` directory.
2.  Activate the plugin through the 'Plugins' menu in WordPress.
3.  Go to the "My Tiny VT" menu.
4.  Enter your VirusTotal API Key and click "Verify & Save".

== Screenshots ==

1.  **Dashboard Overview:** The compact, side-by-side layout showing scan results and logs.
2.  **API Key Settings:** Inline validation and saving for the API key.

== Changelog ==

= 1.1 =
*   Refactored UI to use a compact Toolbar layout.
*   Added Shodan search and Copy to Clipboard shortcuts.
*   Separated CSS and JS assets for better maintainability.
*   Added full support for all 8 VirusTotal status types.

= 1.0 =
*   Initial release.
