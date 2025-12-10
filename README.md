# Network Query Tool
Perform WHOIS, DNS, IP, and network diagnostics.

Official Network Query Tool — available since 1990 at [ns1ns2.com](https://www.ns1ns2.com).

## ⚙️ System Requirements
To run the **Network Query Tool (NQT)**, you’ll need the following environment:

### 🖥️ Server Requirements
- **Operating System:** Linux (recommended: AlmaLinux, Ubuntu, CentOS). Windows Server or macOS also supported.
- **Web Server:** Apache or Nginx with PHP enabled.
- **PHP Version:** 7.4 or newer (PHP 8.x recommended).
- **Required Extensions:**
  - `cURL` (for WHOIS/DNS lookups and external queries)
  - `OpenSSL` (for secure connections)
  - `mbstring` (for string handling)
  - `json` (for structured output)
- **Database:** Optional (MySQL/MariaDB) if you want to log queries.

### 🌐 Client Requirements
- **Browser:** Modern browsers (Edge, Chrome, Firefox, Safari).  
- **Internet Access:** Required for DNS, WHOIS, and IP lookups.

### ⚡ Hardware Requirements
- **Minimal:** 1 CPU core, 512 MB RAM, 200 MB disk space.  
- **Recommended:** 2+ CPU cores, 2 GB RAM, SSD storage for smoother performance.

### 🔒 Security Considerations
- Run behind HTTPS (TLS certificate).  
- Sandbox or rate‑limit queries to prevent abuse.  
- Keep PHP and server packages updated regularly.

## 🌐 Languages
* [English (en-us)](Documentation/README-en.md)
* [Français (fr)](Documentation/README-fr.md)
* [Deutsch (de)](Documentation/README-de.md)
* [हिन्दी (hi)](Documentation/README-hi.md)
* [Español (es)](Documentation/README-es.md)
* [日本語 (ja)](Documentation/README-ja.md)
* [简体中文 (zh-cn)](Documentation/README-zh-cn.md)

## 📄 Documentation
- [Changelog](CHANGELOG.md)
- [License](LICENSE)
