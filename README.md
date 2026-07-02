🛡️ SentinelMail

SentinelMail est un système hybride de détection de phishing conçu pour sécuriser les flux de messagerie professionnelle. En combinant l'intelligence artificielle (Apprentissage Automatique) et l'analyse déterministe des métadonnées réseau, SentinelMail offre une protection proactive contre les menaces modernes (phishing, ransomware, usurpation d'identité) sans compromettre la confidentialité des échanges.

Ce projet a été développé dans le cadre d'un travail de fin d'études pour la protection des infrastructures critiques de la Régie des Voies Aériennes (RVA).
🚀 Fonctionnalités Clés

    Approche Hybride de Sécurité :

        Module IA (Probabiliste) : Classification des e-mails via un modèle de forêt aléatoire (Random Forest) pour identifier les patterns textuels suspects.

        Module Déterministe (Réseau) : Vérification rigoureuse des standards de sécurité DNS (SPF, DKIM, DMARC) et analyse de la réputation des domaines (WHOIS, âge du domaine).

    Intégration Gmail API : Connexion sécurisée via OAuth 2.0. Fini les mots de passe d'application risqués.

    Protection des Données (Vault) : Stockage sécurisé des secrets via le trousseau système (keyring) ou chiffrement AES (Fernet), assurant qu'aucun identifiant ne traîne en clair.

    Forensics Avancé : Analyse binaire des pièces jointes pour détecter les macros malveillantes (Office), les scripts HTML dangereux ou les redirections suspectes.

    Alerte Temps Réel : Notification immédiate via WhatsApp en cas de menace critique détectée.

🛠️ Architecture Technique

Le système est découpé en modules spécialisés pour garantir modularité et performance :

    main.py : Point d'entrée et interface graphique (GUI) développée avec PySide6.

    logic_api.py : Gestionnaire de l'API Gmail et du flux OAuth 2.0.

    logic.py : Moteur central orchestrant l'analyse des emails.

    security_enhanced.py : Le cœur de l'analyse réseau (DNS, Forensics pièces jointes, URL homoglyphes).

    vault.py : Gestionnaire de coffre-fort pour les credentials.

    logic_notify.py : Module d'alerte pour Twilio et WhatsApp.

⚙️ Prérequis

Pour exécuter le projet, assure-toi d'avoir Python 3.x installé, puis installe les dépendances nécessaires :
Bash

pip install -r requirements.txt

Note : Assure-toi d'avoir dnspython, scikit-learn, pandas, cryptography et PySide6 dans ton environnement.
🚀 Installation & Lancement

    Cloner le dépôt :
    Bash

git clone https://github.com/ton-nom-utilisateur/SentinelMail.git
cd SentinelMail

Configuration des API :

    Place ton fichier credentials.json (obtenu depuis la Google Cloud Console) à la racine.

    Configure tes clés Twilio dans config_notify.json si tu souhaites activer les alertes automatiques.

Lancer l'application :
Bash

    python main.py

📊 Résultats & Performances

Le modèle d'apprentissage automatique a été entraîné sur un dataset de 30 000 emails, atteignant des performances robustes :

    Précision globale : ~98%

    Recall (détection des menaces) : ~99%

    F1-Score : 0.98

🛡️ Sécurité & Disclaimer

Ce projet est conçu à des fins académiques et professionnelles pour sécuriser des infrastructures sensibles. Attention : Ne jamais stocker de jetons d'accès ou de fichiers de configuration contenant des secrets dans un dépôt public. Veillez à inclure les fichiers de configuration sensibles dans votre .gitignore.
📜 Licence

Ce projet est sous licence MIT. Vous êtes libre d'utiliser, modifier et distribuer ce code pour vos propres besoins de cybersécurité.
👨‍💻 Auteur

Développé avec passion pour la sécurisation des infrastructures nationales.
