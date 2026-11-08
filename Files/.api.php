<?php
declare(strict_types=1);
http_response_code(200);
$NQT_VERSION = '2.4.4';
/**************************************************************************
 * Network Query Tool                                                     *
 * © 1990-2026 Sipylus LLC.                                               *
 * All rights reserved.                                                   *
 **************************************************************************

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

 **/

// Security & privacy headers
$nonce = bin2hex(random_bytes(32));
$policies = [
    "default-src 'self'",
    // "script-src 'self' 'nonce-$nonce' sipylus.com www.sipylus.com static.statcounter.com secure.statcounter.com www.statcounter.com",
    "script-src 'self' 'unsafe-inline' sipylus.com www.sipylus.com static.statcounter.com secure.statcounter.com www.statcounter.com",
	"style-src 'self' 'nonce-$nonce'",
    "img-src 'self' data: sipylus.com www.sipylus.com c.statcounter.com secure.statcounter.com www.statcounter.com sipylus.montastic.io",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "frame-src 'none'",
    "child-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'"
    // "upgrade-insecure-requests"
];
header("Content-Security-Policy: " . implode('; ', $policies));
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 0');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), usb=(), clipboard-write=(self)');
header('Feature-Policy: clipboard-write');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-site');
header('X-Robots-Tag: noai, noimageai');

// Branding (Brand and Slogan)
$brandName   = 'Network Query Tool';
$brandShort  = 'NQT';
$brandSlogan = 'Professional Diagnostic & IP Tools by Sipylus';

// Theming (Dark and Light Mode Friendly)
$accent      = '#0ea5e9'; // Bright Cyan Blue
$bgLight     = '#f5f7fb'; // Very Light Cool Gray
$cardLight   = '#ffffff'; // White
$textLight   = '#222222'; // Very Dark Gray
$mutedLight  = '#667085'; // Muted Slate Gray

$accentDark  = '#0369a1'; // Deep Cyan Blue
$bgDark      = '#0b0f14'; // Near Black
$cardDark    = '#111827'; // Dark Blue-Gray
$textDark    = '#e5e7eb'; // Very Light Gray
$mutedDark   = '#9ca3af'; // Muted Gray

// Global Privacy Control Signal Detector (Advertisements,  Analytics, Options & Settings)
$gpc = ($_SERVER['HTTP_SEC_GPC'] ?? '') === '1';

// Global Privacy Control Settings
$analyticsAllowed = true;       // do not edit; default = true
$adsAllowed = true;             // do not edit; default = true

// Global Privacy Control Options
if ($gpc) {
    $analyticsAllowed = false;  // set true or false; default = false
    $adsAllowed = false;        // set true or false; default = false
}

// Advertisements and Analytics
if ($analyticsAllowed) {
    //Loading Analytics...
}
if ($adsAllowed) {
    //Loading Affiliates...
}
