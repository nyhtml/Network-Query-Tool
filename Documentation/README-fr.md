## 🖥️ Configuration serveur
- **Système d’exploitation :** Linux (recommandé : AlmaLinux, Ubuntu, CentOS). Windows Server ou macOS également pris en charge.
- **Serveur web :** Apache ou Nginx avec PHP activé.
- **Version PHP :** 7.4 ou plus récent (PHP 8.x recommandé).
- **Extensions requises :**
  - `cURL` (pour les recherches WHOIS/DNS et les requêtes externes)
  - `OpenSSL` (pour les connexions sécurisées)
  - `mbstring` (pour la gestion des chaînes de caractères)
  - `json` (pour la sortie structurée)
- **Base de données :** Optionnelle (MySQL/MariaDB) si vous souhaitez enregistrer les requêtes.

### 🌐 Configuration client
- **Navigateur :** Navigateurs modernes (Edge, Chrome, Firefox, Safari).  
- **Accès Internet :** Requis pour les recherches DNS, WHOIS et IP.

## ⚡ Configuration matérielle
- **Minimum :** 1 cœur CPU, 512 Mo de RAM, 200 Mo d’espace disque.  
- **Recommandé :** 2+ cœurs CPU, 2 Go de RAM, stockage SSD pour de meilleures performances.

## 🔒 Considérations de sécurité
- Exécuter derrière HTTPS (certificat TLS).  
- Mettre en place un bac à sable ou limiter le débit des requêtes pour éviter les abus.  
- Maintenir PHP et les paquets serveur régulièrement à jour.

## 🎯 Fonctionnalités
Le **Network Query Tool** fournit plusieurs fonctionnalités qui en font un outil pratique pour le diagnostic réseau :

📸 NS/Instantané réseau
- **IP externe :** Votre adresse IPv4 et IPv6.
- **Infos de connexion :** Votre port, méthode et protocole.
- **Reverse DNS :** Votre fournisseur d’accès Internet.
- **ASN / Préfixe :** Affiche rapidement votre adresse IPv4 et IPv6.
- **User Agent :** Affiche rapidement votre adresse IPv4 et IPv6.
- **Affichage / Viewport :** Affiche rapidement votre adresse IPv4 et IPv6.
- **Navigateur :** Affiche rapidement les détails de votre navigateur.
- **Appareil :** Affiche les détails de votre appareil connecté à Internet.

🛡️ NS1/Sécurité réseau
- **Confidentialité WHOIS :** Gardez vos informations personnelles hors des registres publics.
- **Proxy web :** Masquez votre IP et votre localisation lors de la navigation.
- **VPN personnel :** Sécurisez votre connexion Internet avec un chiffrement VPN haute vitesse.

🕵️ NS2/Analyse réseau
- **Recherche WHOIS :** Trouvez rapidement des détails sur les enregistrements de domaine.
- **Recherche DNS :** Vérifiez les enregistrements DNS de n’importe quel domaine.
- **DNS direct :** Trouvez le nom de domaine associé à une IP.
- **DNS inverse :** Trouvez le nom de domaine associé à une IP.
- **Recherche d’hôte :** Trouvez l’IP derrière un nom d’hôte ou le domaine derrière une IP.
- **Test Ping :** Vérifiez si un serveur est joignable et mesurez le temps de réponse.
- **Traceroute :** Tracez le chemin emprunté par les données pour atteindre un serveur.
- **Informations IP :** Obtenez des informations détaillées sur une adresse IP.
- **Scan de ports :** Vérifiez quels ports sont ouverts sur un serveur.
- **Recherche RBL :** Vérifiez si une IP est listée sur des blacklists courantes.
- **Vérification d’email :** Confirmez si une adresse email est valide.
- **MonIP :** Trouvez rapidement votre adresse IP publique actuelle.
- **MonIP :** Trouvez rapidement des informations sur une adresse IP publique.
