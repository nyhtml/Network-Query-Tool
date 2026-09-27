<?php
/**************************************************************************
 * Network Query Tool                                                     *
 * Hardened headers, proxy-aware HTTPS, a11y, dark-mode, and UX niceties. *
 * © 1990-2026 Sipylus LLC. All rights reserved.                          *
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
 http_response_code(200);
$NQT_VERSION = '2.4.2';

// Global Privacy Control Signal Detector
$gpc = ($_SERVER['HTTP_SEC_GPC'] ?? '') === '1';

// Global Privacy Control Settings
$analyticsAllowed = true;       // do not edit; default = true
$adsAllowed = true;             // do not edit; default = true

// Page Settings
if ($gpc) {
    $analyticsAllowed = false;  // set true or false; default = false
    $adsAllowed = false;        // set true or false; default = false
}

// Advertisements and Analytics Settings
if ($analyticsAllowed) {
    //Loading Analytics...
}
if ($adsAllowed) {
    //Loading Affiliates...
}
