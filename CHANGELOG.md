# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.6.0]
### Performance Improvements
- Allow the `Network Query Tool` website to reduce bandwidth usage and improve page load times.
  - Implemented early gzip compression support, to reduce bandwidth usage and improve page load times across desktop and mobile devices.
  - Optimized output buffering to ensure headers are sent efficiently, minimizing latency during DNS and WHOIS queries.

### UX Update
- Added "🌙 Mode" and "☀️ Mode" theme for the `Network Query Tool` for desktop and mobile devices.

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
