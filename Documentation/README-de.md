# 🖥️ Serveranforderungen
- **Betriebssystem:** Linux (empfohlen: AlmaLinux, Ubuntu, CentOS). Windows Server oder macOS ebenfalls unterstützt.  
- **Webserver:** Apache oder Nginx mit aktiviertem PHP.  
- **PHP-Version:** 7.4 oder neuer (PHP 8.x empfohlen).  
- **Erforderliche Erweiterungen:**  
  - `cURL` (für WHOIS-/DNS-Abfragen und externe Requests)  
  - `OpenSSL` (für sichere Verbindungen)  
  - `mbstring` (für Zeichenkettenverarbeitung)  
  - `json` (für strukturierte Ausgabe)  
- **Datenbank:** Optional (MySQL/MariaDB), falls Abfragen protokolliert werden sollen.

## 🌐 Client-Anforderungen
- **Browser:** Moderne Browser (Edge, Chrome, Firefox, Safari).  
- **Internetverbindung:** Erforderlich für DNS-, WHOIS- und IP-Abfragen.

## ⚡ Hardwareanforderungen
- **Minimal:** 1 CPU‑Kern, 512 MB RAM, 200 MB Speicherplatz.  
- **Empfohlen:** 2+ CPU‑Kerne, 2 GB RAM, SSD‑Speicher für bessere Performance.

## 🔒 Sicherheitsaspekte
- Betrieb über HTTPS (TLS‑Zertifikat).  
- Abfragen sandboxen oder rate‑limiten, um Missbrauch zu verhindern.  
- PHP und Serverpakete regelmäßig aktualisieren.

## 🎯 Funktionen
Das Network Query Tool bietet zahlreiche Funktionen, die es zu einem praktischen Werkzeug für Netzwerkdiagnosen machen:

### 📸 NS / Network Snapshot
- **Externe IP:** Ihre IPv4‑ und IPv6‑Adresse.  
- **Verbindungsinformationen:** Port, Methode und Protokoll.  
- **Reverse DNS:** Ihr Internetanbieter.  
- **ASN / Präfix:** Schnelle Ansicht Ihrer IPv4‑ und IPv6‑Adresse.  
- **User Agent:** Details zu Ihrem Browser und System.  
- **Display / Viewport:** Informationen zu Bildschirm und Ansicht.  
- **Browser:** Details zu Ihrem Browser.  
- **Gerät:** Informationen zu Ihrem internetfähigen Gerät.

### 🛡️ NS1 / Network Security
- **WHOIS‑Privatsphäre:** Persönliche Kontaktdaten aus öffentlichen Registern fernhalten.  
- **Web‑Proxy:** IP‑Adresse und Standort beim Surfen verschleiern.  
- **Persönliches VPN:** Internetverbindung mit schneller VPN‑Verschlüsselung sichern.

### 🕵️ NS2 / Network Scanning
- **WHOIS‑Abfrage:** Details zu Domainregistrierungen abrufen.  
- **DNS‑Abfrage:** DNS‑Einträge einer Domain prüfen.  
- **Forward DNS Lookup:** Domainnamen zu einer IP finden.  
- **Reverse DNS Lookup:** Domainnamen zu einer IP finden.  
- **Host Finder:** IP hinter einem Hostnamen oder Domain hinter einer IP ermitteln.  
- **Ping‑Test:** Erreichbarkeit eines Servers prüfen und Antwortzeiten messen.  
- **Traceroute:** Den Pfad verfolgen, den Daten zu einem Server nehmen.  
- **IP‑Informationen:** Detaillierte Informationen zu einer IP‑Adresse.  
- **Portscan:** Offene Ports auf einem Server prüfen.  
- **RBL‑Abfrage:** Prüfen, ob eine IP auf Blacklists gelistet ist.  
- **E‑Mail‑Check:** Validität einer E‑Mail‑Adresse prüfen.  
- **MyIP:** Öffentliche IP‑Adresse anzeigen.  
- **MyIP (Info):** Informationen zu einer öffentlichen IP‑Adresse abrufen.
