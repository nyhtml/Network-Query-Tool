# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

---

📦 Feature Updates
- New functionality added to the tool (e.g., introducing a new lookup type like DNSSEC validation or adding IPv6 support).
- Expands what the software can do beyond its original scope.

🛠️ Bug Fixes
- Corrections for errors, crashes, or misbehaviors (e.g., fixing a traceroute timeout issue or resolving incorrect WHOIS parsing).
- Usually small but critical for stability.

⚡ Performance Improvements
- Optimizations to make the tool faster or more efficient (e.g., reducing query latency, caching DNS results).
- Can also include resource usage improvements for mobile devices.

🔄 Compatibility Updates
- Ensuring the tool works with new browsers, operating systems, or protocols (e.g., Chrome/Edge PWA support, TLS 1.3 compatibility).
- Keeps the tool usable as environments evolve.

📚 Documentation Updates
- Changes to README files, help guides, or inline tooltips.
- Often overlooked, but critical for user comfort and onboarding.

🧪 Experimental / Beta Updates
- Features marked as “pre-release” or “beta” for testing (e.g., experimental port scanning modes).
- Allows feedback before full rollout.

---

## [2.3.0]
### Security Update
- Allow the `Network Query Tool` website to implement a 16-byte nonce for the Content Security Policy (CSP).
- Increased the bits to align with common modern security practices
  - Change `$nonce = bin2hex(random_bytes(12));` to `$nonce = bin2hex(random_bytes(16));`

## [2.2.3]
### Security Update
- Allow the `Network Query Tool` website to implement a bulletproof version of the Content Security Policy (CSP).
- Improved CSP nonce.
  - From `<script>` to `<script nonce="<?php echo $nonce; ?>">`
  - From `<style>` to `<style nonce="<?php echo $nonce; ?>">`

## [2.2.2]
### Bug Fixes
- Allow the `Network Query Tool` website to display without a warning when hosted on the Windows platform.
  - Convert the CSP header into a single line.

## [2.2.1]
### Performance Improvements
- Allow the `Network Query Tool` website to perform port scanning on Windows.
  -  returns immediately on non‑responsive ports.
  - Prevents long execution delays.

## [2.2.0]
### UX Update
- Configured the `Network Query Tool` website to provide additional options on HTTP Errors.
  - Go Home
  - Try Again
  - Display a Request ID

## [2.1.0]
### Performance Improvements
- Allow the `Network Query Tool` website to have long‑term browser caching support across desktop and mobile devices.
  - Enhanced installability, theme handling, and overall responsiveness for modern browsers.
  - Refined caching behavior to provide faster repeat loads and smoother navigation.

## [2.0.0]
### UX Update
- Improved the PWA Support for the `Network Query Tool` website for desktop and mobile devices.

## [1.9.0]
### Security Update
- Allow the `Network Query Tool` website to implement HTTP Strict Transport Security (HSTS) with a long duration deployed on the server.
- Added support for TLS 1.3.
  - Faster handshakes (1 round trip instead of 2)
  - Stronger default ciphers
  - Removal of legacy, insecure algorithms
  - Better privacy (more of the handshake is encrypted)
  - Lower latency for every HTTPS request

## [1.8.0]
### Bug Fixes
- Allow the `Network Query Tool` website to pass HTML5 validation while reducing bandwidth usage and page load times.
  - Moved the early gzip compression support from all pages to the .htaccess file.

## [1.7.0]
### UX Update
- Added "🌙 Mode" and "☀️ Mode" in the theme for the `Network Query Tool` website for desktop and mobile devices.

## [1.6.0]
### Performance Improvements
- Allow the `Network Query Tool` website to reduce bandwidth usage and improve page load times.
  - Implemented early gzip compression support, to reduce bandwidth usage and improve page load times across desktop and mobile devices.
  - Optimized output buffering to ensure headers are sent efficiently, minimizing latency during DNS and WHOIS queries.

## [1.5.0]
### Security Update
- Allowed the `Network Query Tool` website from being accessed by specific user-agents. 

## [1.4.0]
### UX Update
- Added dark mode detection and theme to the `Network Query Tool` for desktop and mobile devices.

## [1.3.0]
### UX Update
- Improve the `Network Query Tool` responsiveness on mobile devices.
  - Links and tap targets are sufficiently large and touch-friendly
  - Page content fits device width
  - Text on the page is readable

## [1.2.0]
### Security Update
- Strengthen the `Network Query Tool` security & privacy headers.

## [1.1.0]
### Security Update
- Prevent the `Network Query Tool` from allowing the execution of arbitrary commands on the host system.

## [1.0.0]
### Initial release
- Initial release of the `Network Query Tool` website.
