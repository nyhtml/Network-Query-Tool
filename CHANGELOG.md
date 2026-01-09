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
