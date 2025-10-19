<?php
/**
 * index.php — (Live Version)
 * Hardened headers, proxy-aware HTTPS, a11y, dark-mode, and UX niceties.
 * ns1ns2.com via ns.sipylus.com
 */

// Early gzip (if available)
if (!headers_sent()) {
    if (extension_loaded('zlib') && function_exists('ob_gzhandler')) {
        ob_start('ob_gzhandler');
    } else {
        ob_start();
    }
}

// Proxy-aware HTTPS detection
function is_https(): bool {
    // Direct HTTPS or port 443
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') return true;
    if (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) return true;

    // Common proxy headers (Cloudflare, generic reverse proxies)
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') return true;
    if (!empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower($_SERVER['HTTP_FRONT_END_HTTPS']) !== 'off') return true;
    if (!empty($_SERVER['HTTP_CF_VISITOR']) && strpos($_SERVER['HTTP_CF_VISITOR'], 'https') !== false) return true;

    return false;
}

if (!is_https()) {
    $host = $_SERVER['HTTP_HOST'] ?? 'ns1ns2.com';
    $uri  = $_SERVER['REQUEST_URI'] ?? '/';
    header('Location: https://' . $host . $uri, true, 301);
    exit;
}

// Security & privacy headers
$nonce = bin2hex(random_bytes(12));
$policies = [
    "default-src 'self'",
    "style-src 'self' 'nonce-$nonce'",
    "script-src 'self' 'nonce-$nonce' sipylus.com www.sipylus.com static.statcounter.com secure.statcounter.com www.statcounter.com",
    "img-src 'self' data: sipylus.com www.sipylus.com c.statcounter.com secure.statcounter.com www.statcounter.com",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'"
];

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), usb=()');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-site');
header('X-Robots-Tag: noai, noimageai');

// Visitor info helpers
function client_ip(): string {
    $headers = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR'
    ];
    foreach ($headers as $h) {
        if (!empty($_SERVER[$h])) {
            $ip = $_SERVER[$h];
            if ($h === 'HTTP_X_FORWARDED_FOR') {
                // left-most public IP
                $parts = array_map('trim', explode(',', $ip));
                $ip = $parts[0] ?? $ip;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return '0.0.0.0';
}

function reverse_dns(string $ip): string {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
    $host = @gethostbyaddr($ip);
    return ($host && $host !== $ip) ? $host : '';
}

/**
 * Team Cymru ASN lookup via whois (TCP, no ext deps).
 * Falls back silently if unavailable.
 */
function asn_lookup(string $ip): array {
    $result = ['asn' => '', 'holder' => '', 'cc' => '', 'prefix' => ''];
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return $result;

    $sock = @fsockopen('whois.cymru.com', 43, $errno, $errstr, 2.5);
    if (!$sock) return $result;

    stream_set_timeout($sock, 3);
    fwrite($sock, "-f -o -p $ip\r\n");

    $data = '';
    while (!feof($sock)) { $data .= fgets($sock, 512); }
    fclose($sock);

    $lines = array_values(array_filter(array_map('trim', explode("\n", $data))));
    if ($lines) {
        $line = $lines[count($lines)-1];
        $parts = array_map('trim', explode('|', $line));
        if (count($parts) >= 8 && preg_match('/^\d+$/', $parts[0])) {
            $result['asn']    = 'AS' . $parts[0];
            $result['cc']     = $parts[1] ?? '';
            $result['holder'] = $parts[7] ?? ($parts[4] ?? '');
            $result['prefix'] = $parts[5] ?? '';
        }
    }
    return $result;
}

$ip = client_ip();

if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $ipv6 = $ip;
    $ipv4 = 'Not detected';
} elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    $ipv4 = $ip;
    $ipv6 = 'Not detected';
} else {
    $ipv4 = 'Not detected';
    $ipv6 = 'Not detected';
}

$rdns = reverse_dns($ip);
$asn  = asn_lookup($ip);
$ua   = $_SERVER['HTTP_USER_AGENT'] ?? '';
$now  = new DateTime('now', new DateTimeZone('America/New_York'));

// Theming (Dark and Light Mode Friendly)
$brandName   = 'Network Query Tool';
$brandShort  = 'Sipylus';
$accent      = '#0ea5e9';
$accentDark  = '#0369a1';
$bgLight     = '#f5f7fb';
$cardLight   = '#ffffff';
$textLight   = '#222';
$mutedLight  = '#667085';

$bgDark      = '#0b0f14';
$cardDark    = '#111827';
$textDark    = '#e5e7eb';
$mutedDark   = '#9ca3af';

/* --- Host finder logic --- */
function host_finder(string $target): array {
    $results = [];

    // Normalize
    $target = trim($target);
    if (!$target) return [];

    // Case: IP → resolve reverse DNS
    if (filter_var($target, FILTER_VALIDATE_IP)) {
        $host = @gethostbyaddr($target);
        if ($host && $host !== $target) $results[] = $host;
        return $results ?: ["(No hostnames found for $target)"];
    }

    // Case: Hostname → try to brute-force subdomains (small demo dictionary)
    $dict = ['www','mail','ftp','api','dev','test'];
    $domain = $target;

    foreach ($dict as $sub) {
        $fqdn = "$sub.$domain";
        $res = @dns_get_record($fqdn, DNS_A + DNS_AAAA);
        if (!empty($res)) {
            $results[] = $fqdn . ' → ' . implode(', ', array_column($res, 'ip'));
        }
    }

    return $results ?: ["(No hosts resolved for $target)"];
}

$scanResults = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['input'])) {
    $scanResults = host_finder($_POST['input']);
}
?>
<!-- Copyright © Sipylus LLC.
       All rights reserved. --!>
<!doctype html>
<html lang="en-US" data-build="prod-<?= $nonce ?>" dir="ltr" class="">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title><?= htmlspecialchars($brandName) ?> - Network Query, Diagnostics &amp; IP Tools</title>
  <meta name="description" content="Perform WHOIS, DNS, IP, and network diagnostics with <?= htmlspecialchars($brandShort) ?>. Discover your IP address, reverse DNS lookup, and use diagnostic tools like IP WHOIS, ping, and traceroute to check your connection and network health.">
  <meta name="keywords" content="NS1NS1, NS1 N2, NS1, NS2, NS, Network Seeker, Network Snapshot, Network Security, Network Scanning, my ip address, what is my ip address, ip health, reverse lookup DNS hostname, connection health, dns query, ip whois, traceroute, ping, find my ip address, get my I.P. address">

  <link rel="manifest" href="/site.webmanifest">
  <link rel="icon" href="https://www.sipylus.com/favicon.ico">
  <meta name="theme-color" content="<?= $accent ?>">
  <style nonce="<?= $nonce ?>">
    :root{
      --accent: <?= $accent ?>; --accentDark: <?= $accentDark ?>;
      --bg: <?= $bgLight ?>; --card: <?= $cardLight ?>; --text: <?= $textLight ?>; --muted: <?= $mutedLight ?>;
      --ring: rgba(14,165,233,.45);
      --shadow: 0 2px 6px rgba(0,0,0,0.08);
      --shadow-lg: 0 8px 24px rgba(0,0,0,0.16);
      --radius: 14px;
    }
    @media (prefers-color-scheme: dark) {
      :root{
        --bg: <?= $bgDark ?>; --card: <?= $cardDark ?>; --text: <?= $textDark ?>; --muted: <?= $mutedDark ?>;
        --ring: rgba(14,165,233,.35);
        --shadow: 0 2px 6px rgba(0,0,0,0.5);
        --shadow-lg: 0 8px 24px rgba(0,0,0,0.6);
      }
    }
    *{box-sizing:border-box}
    html,body{margin:0;padding:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif}
    a{color:inherit;text-decoration:none}
    a:focus-visible{outline:3px solid var(--ring); outline-offset:3px; border-radius:10px}
    .wrap{max-width:1100px;margin:0 auto;padding:32px}
    header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:28px}
    .brand{display:flex;align-items:center;gap:12px}
    .logo{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,var(--accent),var(--accentDark));display:grid;place-items:center;font-weight:800;color:#fff}
    .title{font-size:clamp(20px,3vw,28px);font-weight:750}
    .tag{color:var(--muted);font-size:14px}
    .card{background:var(--card);border:1px solid rgba(2,6,23,.14);border-radius:16px;padding:20px;box-shadow:var(--shadow)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
    .tool{background:var(--card);border:1px solid rgba(2,6,23,.12);border-radius:14px;padding:16px;transition:transform .15s ease, box-shadow .15s ease, border-color .15s ease}
    .tool:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg);border-color:var(--accent)}
    .tool h2,.tool h3{margin:0 0 6px 0;font-size:16px}
    .tool p{margin:0;font-size:14px;color:var(--muted)}
    .cta{display:inline-block;margin-top:10px;padding:10px 14px;border-radius:12px;background:var(--accent);color:#fff;font-weight:700}
    .cta:hover{background:var(--accentDark)}
    footer{margin-top:28px;color:var(--muted);font-size:14px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between}
    .pill{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:rgba(2,6,23,.04);border:1px solid rgba(2,6,23,.12)}
    code.small{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
    .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
    @media (prefers-reduced-motion: reduce){*{transition:none !important;scroll-behavior:auto !important}}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <div class="logo" aria-hidden="true">🕵</div>
        <div>
          <div class="title"><a title="<?= htmlspecialchars($brandName) ?>" href="/"><?= htmlspecialchars($brandName) ?></a></div>
          <div class="tag"><a title="WHOIS • DNS • IP • Tools">WHOIS • DNS • IP • Tools</a></div>
        </div>
      </div>
      <a class="cta" href="/#tools" aria-label="Skip to tools">Open Tools</a>
    </header>

    <div class="card" id="intro" role="region" aria-label="Introduction">
        <p>
            The <strong><a title="<?= htmlspecialchars($brandName) ?>" href="https://www.ns1ns2.com"><?= htmlspecialchars($brandName) ?></a></strong> is a service developed with 
            <strong><a title="Sipylus AI" href="https://ai.sipylus.com" target="_blank">Sipylus AI</a></strong> technology, designed to deliver fast, privacy-respecting network lookups for operators and researchers.
            No tracking pixels. No ad beacons. Just the data you asked for. You can self-host the tool or script against its endpoints. For high-volume access to the research tools, please contact the <a href="/contact/#operationss">Operations</a> team.
        </p>
    </div>

    <h1 style="margin:24px 0 8px 0">📸 NS/Network Snapshot</h1>
    <section class="grid" id="session" aria-label="Visitor details">
      <a class="tool" title="External IP" aria-label="Client IP">
        <h2>📍 External IP</h2>
        <p><code class="small" title="Your IPv4 address."><strong>IPv4:</strong> <?= htmlspecialchars($ipv4) ?></code></p>
        <p><code class="small" title="Your IPv6 address, if available."><strong>IPv6:</strong> <?= htmlspecialchars($ipv6) ?></code></p>
      </a>

      <a class="tool" title="Connection Info" aria-label="Connection Info">
        <h2>🔌 Connection Info</h2>
        <p><code class="small" title="The port used for the connection."><strong>Port:</strong> <?= htmlspecialchars($_SERVER['REMOTE_PORT'] ?? 'N/A') ?></code></p>
        <p><code class="small" title="The method used for the connection."><strong>Method:</strong> <?= htmlspecialchars($_SERVER['REQUEST_METHOD'] ?? 'N/A') ?></code></p>
        <p><code class="small" title="The protocol used for the connection."><strong>Protocol:</strong> <?= htmlspecialchars($_SERVER['SERVER_PROTOCOL'] ?? 'N/A') ?></code></p>
      </a>


      <a class="tool" title="Reverse DNS" aria-label="Reverse DNS">
        <h2>🔄 Reverse DNS</h2>
        <p><code class="small"><?= htmlspecialchars($rdns ?: '—') ?></code></p>
      </a>

      <a class="tool" title="ASN / Prefi" aria-label="ASN and Prefix">
        <h2>🛰️ ASN / Prefix</h2>
        <p><code class="small"><?= htmlspecialchars(($asn['asn'] ?: '—') . ($asn['prefix'] ? ' · ' . $asn['prefix'] : '')) ?></code></p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;"><?= htmlspecialchars($asn['holder'] ?: '') ?></p>
      </a>

      <a class="tool" title="User Agent" aria-label="User Agent">
        <h2>🖥️ User Agent</h2>
        <p><code class="small" style="word-break:break-all;display:block;max-width:100%"><?= htmlspecialchars($ua) ?></code></p>
      </a>

      <a class="tool" title="Display / Viewport" aria-label="Display / Viewport">
        <h2>🖥️ Display / Viewport</h2>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">Physical: <code id="vpPhysical">—</code></p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">Pixel: <code id="screenLogical">—</code></p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">Available: <code id="avail">—</code></p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">Color Depth: <code id="colorDepth">—</code></p>
        <p>Appearance: <span id="colorMode">—</span></p>
        <noscript>
        <p style="color:#fca5a5;font-size:12px;">Enable JavaScript to see display details.</p>
        </noscript>
      </a>

      <a class="tool" title="Browser" aria-label="Browser">
        <h2>🖥️ Browser</h2>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">Viewport: <code id="vpLogical">—</code></p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">DPR: <code id="dpr">—</code></p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">Resolution: <code id="screenPhysical">—</code></p>
        <noscript>
        <p style="color:#fca5a5;font-size:12px;">Enable JavaScript to see display details.</p>
        </noscript>
      </a>

    <a class="tool" title="Device" aria-label="Device">
        <h2>📱️ Device</h2>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">
          Network: <code id="net">—</code>
        </p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">
          Device RAM: <code id="mem">—</code>
        </p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">
          Time zone: <code id="tz">—</code>
        </p>
        <p style="color:var(--muted);font-size:12px;margin-top:6px;">
          Local time: <code id="localTime">—</code>
        </p>
        <noscript><p style="color:#fca5a5;font-size:12px;">Enable JavaScript to see display details.</p></noscript>
      </a>

    </section>

    <h1 style="margin:24px 0 8px 0">🛡️ NS1/Network Security</h1>
    <section class="grid" id="protect" aria-label="Network Security">
      <a class="tool" href="https://whois.sipylus.com/" target="_blank" aria-label="WHOIS Privacy">
        <h2>🛡️ WHOIS Privacy</h2>
        <p>Keep personal contact info off public records.</p>
      </a>
      <a class="tool" href="https://proxy.sipylus.com/" target="_blank" aria-label="Web Proxy">
        <h2>🛡️ Web Proxy</h2>
        <p>Mask your IP and location while browsing.</p>
      </a>
      <a class="tool" href="https://vpn.sipylus.com/" target="_blank" aria-label="SipylusVPN">
        <h2>🛡️ SipylusVPN</h2>
        <p>Secure your internet connection with high-speed VPN encryption.</p>
      </a>
      <a class="tool" href="#NordVPN" target="_blank" aria-label="NordVPN">
        <h2>🛡️ NordVPN</h2>
        <p>Protect your browsing with military-grade encryption and ultra-fast servers worldwide.</p>
      </a>
      <a class="tool" href="#Surfshark" target="_blank" aria-label="Surfshark">
        <h2>🛡️ Surfshark</h2>
        <p>Browse securely on unlimited devices with a fast, no-logs VPN you can trust.</p>
      </a>
      <a class="tool" href="#IPVanish" target="_blank" aria-label="IPVanish">
        <h2>🛡️ IPVanish</h2>
        <p>Encrypt your internet traffic and gain full control of your online privacy.</p>
      </a>
      <a class="tool" href="#CyberGhost" target="_blank" aria-label="CyberGhost">
        <h2>🛡️ CyberGhost</h2>
        <p>Stay anonymous online with user-friendly VPN protection and global server coverage.</p>
      </a>
      <a class="tool" href="#ExpressVPN" target="_blank" aria-label="ExpressVPN">
        <h2>🛡️ ExpressVPN</h2>
        <p>Access the internet freely and securely with lightning-fast VPN connections.</p>
      </a>
    </section>

    <h1 style="margin:20px 0 10px 0">🕵️ NS2/Network Scanning</h1>
    <section class="grid" id="tools" aria-label="Network Scanning">
      <a class="tool" href="/tools/whois.php" aria-label="WHOIS Lookup">
        <h2>🔍 WHOIS Lookup</h2>
        <p>Domain registrant and registry info.</p>
      </a>
      <a class="tool" href="/tools/dns.php" aria-label="DNS Lookup">
        <h2>🌐 DNS Lookup</h2>
        <p>A, AAAA, MX, NS, TXT, CNAME, SOA, DS (DNSSEC).</p>
      </a>
      <a class="tool" href="/tools/fdns.php" aria-label="Forward DNS">
        <h2>➡️ Forward DNS</h2>
        <p>Resolve a domain name or server to its IP address.</p>
      </a>
      <a class="tool" href="/tools/rdns.php" aria-label="Reverse DNS">
        <h2>↩️ Reverse DNS</h2>
        <p>PTR resolution with validation and hints.</p>
      </a>
      <a class="tool" href="/tools/hostfinder.php" aria-label="IP Info">
        <h2>🔄 Host Finder</h2>
        <p>Find the IP behind a hostname, or discover the domain name behind an IP address.</p>
      </a>
      <a class="tool" href="/tools/ping.php" aria-label="Ping Test">
        <h2>📡 Ping Test</h2>
        <p>ICMP echo tests from multiple POPs.</p>
      </a>
      <a class="tool" href="/tools/traceroute.php" aria-label="Traceroute">
        <h2>🛤️ Traceroute</h2>
        <p>MTR-style hops and packet loss overview.</p>
      </a>
      <a class="tool" href="/tools/portscan.php" aria-label="Port Scanner">
        <h2>🚪 Port Scanner</h2>
        <p>TCP/UDP scan with optional service detection.</p>
      </a>
      <a class="tool" href="/tools/rbl.php" aria-label="RBL Check">
        <h2>🚫 RBL Check</h2>
        <p>Multi-DNSBL checks with delist guidance.</p>
      </a>
      <a class="tool" href="/tools/email-check.php" aria-label="Email Checker">
        <h2>✉️ Email Checker</h2>
        <p>Syntax, MX, and basic deliverability checks.</p>
      </a>
      <a class="tool" href="/tools/myip.php" aria-label="What’s my IP">
        <h2>📍 What’s my IP</h2>
        <p>Your IP, rDNS, and ASN at a glance.</p>
      </a>
      <a class="tool" href="/tools/ip.php" aria-label="IP Info">
        <h2>📍 IP Info</h2>
        <p>Geolocation, ASN, prefix, registry, bogon checks.</p>
      </a>
    </section>

    <br>
    <div class="card" id="outro" role="region" aria-label="Conclusion">
    Copyright &copy; 1990-<?php echo date('Y'); ?> 
    <strong><a title="Sipylus" href="https://www.stephanpringle.com">Stephan Pringle</a></strong>. All rights reserved.<br>
    Viewing on <span id="clock" class="datetime" style="line-height: 1;">
      <script src="https://www.sipylus.com/global/scripts/js/datetime.js"></script>
    </span><br>
    Accessed from 
    <a title="<?= htmlspecialchars($ipv4) ?>" href="https://www.ns1ns2.com/#<?= htmlspecialchars($ipv4) ?>" target="_top">
      <?= htmlspecialchars($ipv4) ?>
    </a>
    <p><strong>Sipylus</strong>, the <strong>Sipylus</strong> logo, and other <strong>Sipylus</strong> marks are the exclusive properties and assets of <strong><a title="Sipylus, LLC" href="https://www.sipylus.com">Sipylus, LLC</a></strong>.<br>
    These trademarks are registered and may be registered in the U.S. and in other countries.<br>
    Use of this site signifies your acceptance of Sipylus's <a title="Terms of Use" href="https://www.sipylus.com/legal/terms-of-use/" target="_blank">Terms of Use</a>.</p>
    </div>

    <footer>
      <div class="pill">🔌 <strong>Port:</strong> <?= htmlspecialchars($_SERVER['REMOTE_PORT'] ?? 'N/A') ?></div>
      <div class="pill">📡 <strong>Method:</strong> <?= htmlspecialchars($_SERVER['REQUEST_METHOD'] ?? 'N/A') ?></div>
      <div class="pill">🛰️ <strong>Protocol:</strong> <?= htmlspecialchars($_SERVER['SERVER_PROTOCOL'] ?? 'N/A') ?></div>
      <div class="pill">⏰ <strong>Time:</strong> <?= $now->format('Y-m-d H:i:s T') ?></div>
    </footer>
  </div>

  <!-- Optional: PWA install prompt (non-blocking) -->
  <!-- Service Worker Registration -->
  <script>
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/service-worker.js")
        .then(function(reg) { console.log("✅ Service Worker registered:", reg.scope); })
        .catch(function(err) { console.error("❌ SW registration failed:", err); });
    }

    var deferredPrompt;
    var installBtn = document.getElementById("installBtn");
    window.addEventListener("beforeinstallprompt", function(e) {
      e.preventDefault();
      deferredPrompt = e;
      installBtn.style.display = "inline-block";
    });
    installBtn.addEventListener("click", function() {
      installBtn.style.display = "none";
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(function(choice) {
        console.log("PWA install outcome:", choice.outcome);
        deferredPrompt = null;
      });
    });
  </script>
  <script>
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/service-worker.js')
        .then(reg => console.log('SW registered:', reg))
        .catch(err => console.error('SW registration failed:', err));
    }
  </script>

<!-- Service Worker Registration -->

<!-- Service Worker Registration -->

<!-- Device/viewport details -->
  
<script nonce="<?= $nonce ?>">
  const modeEl = document.getElementById('colorMode');

  function updateMode(e) {
    const isDarkMode = e.matches;
    if(modeEl) modeEl.textContent = isDarkMode ? '🌙 Mode' : '☀️ Mode';
  }

  const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  // Initial set
  updateMode(darkQuery);

  // Listen for changes
  darkQuery.addEventListener('change', updateMode);
</script>
  
  <script nonce="<?= $nonce ?>">
    (function(){
      function $(id){ return document.getElementById(id); }
      function set(id, val){ var el = $(id); if (el) el.textContent = val; }
      function fmt(w,h){ return (w|0) + " × " + (h|0); }

      function update(){
        var dpr = window.devicePixelRatio || 1;

        var iw = window.innerWidth  || document.documentElement.clientWidth || 0;
        var ih = window.innerHeight || document.documentElement.clientHeight || 0;
        set('vpLogical',  fmt(iw, ih));
        set('vpPhysical', fmt(Math.round(iw*dpr), Math.round(ih*dpr)));
        set('dpr', (Math.round(dpr*100)/100).toString().replace(/\.00$/,''));

        var sw = screen.width  || 0;
        var sh = screen.height || 0;
        set('screenLogical',  fmt(sw, sh));
        set('screenPhysical', fmt(Math.round(sw*dpr), Math.round(sh*dpr)));

        var aw = screen.availWidth  || 0;
        var ah = screen.availHeight || 0;
        set('avail', fmt(aw, ah));

        var depth = screen.colorDepth || screen.pixelDepth || 24;
        set('colorDepth', depth + "-bit");

        var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (c){
          var parts = [];
          if (c.effectiveType) parts.push(c.effectiveType);
          if (typeof c.downlink === 'number') parts.push(c.downlink + "Mbps");
          if (typeof c.rtt === 'number') parts.push(c.rtt + "ms");
          set('net', parts.join(' · ') || '—');
        } else { set('net','—'); }

        if (navigator.deviceMemory){ set('mem', navigator.deviceMemory + " GB"); }
        else { set('mem','—'); }

        try { set('tz', Intl.DateTimeFormat().resolvedOptions().timeZone || '—'); }
        catch(e){ set('tz','—'); }
        set('localTime', new Date().toLocaleString());
      }

      update();
      window.addEventListener('resize', update, {passive:true});
      window.addEventListener('orientationchange', update, {passive:true});
      document.addEventListener('visibilitychange', function(){ if (!document.hidden) update(); }, {passive:true});
    })();
  </script>
<!-- Start of StatCounter Code -->
<script>
  var sc_project = 4961761;
  var sc_invisible = 1;
  var sc_security = "eeb7b44c";
  var scJsHost = ("https:" == document.location.protocol) ? "https://secure." : "http://www.";
  document.write("<script src='" + scJsHost + "statcounter.com/counter/counter.js'></" + "script>");
</script>
<noscript>
  <div class="statcounter">
    <img src="https://c.statcounter.com/4961761/0/eeb7b44c/1/" alt="">
  </div>
</noscript>
<!-- End of StatCounter Code -->
</body>
</html>
<?php ob_end_flush(); ?>
<!-- © 1990 Sipylus LLC. All rights reserved.
    _____     _  ___   ___   ___    ____  _             _               _     _     ____   
   / ___ \   / |/ _ \ / _ \ / _ \  / ___|(_)_ __  _   _| |_   _ ___    | |   | |   / ___|  
  / / __| \  | | (_) | (_) | | | | \___ \| | '_ \| | | | | | | / __|   | |   | |  | |      
 | | (__   | | |\__, |\__, | |_| |  ___) | | |_) | |_| | | |_| \__ \_  | |___| |__| |___ _ 
  \ \___| /  |_|  /_/   /_/ \___/  |____/|_| .__/ \__, |_|\__,_|___( ) |_____|_____\____(_)
   \_____/_ _        _       _     _       |_|    |___/            |/              _       
    / \  | | |  _ __(_) __ _| |__ | |_ ___   _ __ ___  ___  ___ _ ____   _____  __| |      
   / _ \ | | | | '__| |/ _` | '_ \| __/ __| | '__/ _ \/ __|/ _ \ '__\ \ / / _ \/ _` |      
  / ___ \| | | | |  | | (_| | | | | |_\__ \ | | |  __/\__ \  __/ |   \ V /  __/ (_| |_     
 /_/   \_\_|_| |_|  |_|\__, |_| |_|\__|___/ |_|  \___||___/\___|_|    \_/ \___|\__,_(_)    
                       |___/                                                               
-->