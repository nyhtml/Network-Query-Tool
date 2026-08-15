## 🖥️ Server Requirements
- **Operating System:** Linux (recommended: AlmaLinux, Ubuntu, CentOS). Windows Server or macOS is also supported.
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

## ⚡ Hardware Requirements
- **Minimal:** Suitable for basic command‑line usage and lightweight queries
  - 1 CPU core
  - 512 MB RAM
  - 200 MB disk space.

- **Recommended:** Suitable for concurrent scans, web UI, and larger datasets
  - 2+ CPU cores
  - 2-4 GB RAM
  - SSD storage for smooth performance.

- **Optimal:** Ideal for heavy logging, large result sets, and multi-threaded operations.
  - 4+ CPU cores
  - 4 GB RAM
  - SSD/NVMe storage for smoother performance.

## 🔒 Security Considerations
- Run behind HTTPS with a valid TLS certificate.
- Rate-limit and restrict queries to help prevent abuse.
- Keep PHP and server packages regularly updated.
- Use a host-based firewall appropriate for your operating system.
- Use intrusion-prevention tools such as Fail2Ban where supported.
- Use a web application firewall (WAF), such as ModSecurity, where supported.
- On Linux servers, consider additional security tools such as ConfigServer Security & Firewall (CSF).

## 🎯 Features
The Network Query Tool provides several features that make it a handy tool for network diagnostics:

📸 NS/Network Snapshot
- **External IP:** Your IPv4 and IPv6 address.
- **Connection Info:** Your port, method, and protocol.
- **Reverse DNS:** Your Internet Service Provider.
- **ASN / Prefix:** Quickly view your IPv4 and IPv6 address.
- **User Agent:** Quickly view your IPv4 and IPv6 address.
- **Display / Viewport:** Quickly view your IPv4 and IPv6 address.
- **Browser:** Quickly view your browser details.
- **Device:** View your Internet-capable device details.

🛡️ NS1/Network Security
- **WHOIS Privacy:** Keep personal contact info off public records.
- **Web Proxy:** Mask your IP and location while browsing.
- **Personal VPN:** Secure your internet connection with high-speed VPN encryption.

🕵️ NS2/Network Scanning
- **WHOIS Lookup:** Quickly find details about domain registrations.
- **RDAP Lookup:** Quickly find structured registration data.
- **DNS Lookup:** Check DNS records for any domain.
- **Forward DNS Lookup:** Find the domain name associated with an IP.
- **Reverse DNS Lookup:** Find the domain name associated with an IP.
- **Host Finder:** Find the IP behind a hostname, or the domain name behind an IP.
- **Ping Test:** Check if a server is reachable and measure the response.
- **Traceroute:** Trace the path data takes to reach a server.
- **IP Information:** Get detailed information about an IP address.
- **Port Scan:** Check which ports are open on a server.
- **RBL Lookup:** Check if an IP is listed on common blacklists.
- **Email Checker:** Verify if an email address is valid.
- **IP Info:** Quickly find your current public IP address.
- **Robots.txt Checker:** Check robots.txt presence and HTTP status.
