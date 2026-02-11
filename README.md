# 🛡️ SentinelMail ULTIMATE V4
> **L'Intelligence Artificielle au service de votre sécurité mail.**

SentinelMail est une sentinelle de défense qui analyse chaque message entrant pour détecter les tentatives de phishing avant que vous ne cliquiez.

### 🔍 Caractéristiques principales :
* 🤖 **Analyse IA (Random Forest)** : Détecte le vocabulaire suspect.
* 🌍 **Geo-Tracking** : Localise l'origine du serveur (DNS/MX).
* 📱 **Détection QR Code** : Analyse les liens cachés dans les images via OpenCV.
* 📄 **Analyse PDF Binaire** : Scanne les scripts malveillants (`/JavaScript`).
* 🔗 **Inspection d'URL** : Repère les adresses IP directes et domaines risqués.
* 🧠 **Score d'Explicabilité** : Comprenez pourquoi un mail est jugé dangereux.

### 💻 Stack Technique :
`Python` | `PySide6` | `Scikit-Learn` | `OpenCV` | `IMAP/SSL`

### 📸 Aperçus de l'application

**1. Interface de Connexion**
![Connexion](images/interface_connexion.png)

**2. Interface d'Affichage des Emails**
![Affichage](images/interface_affichage.png)

**3. Interface d'Explicabilité (IA)**
![Explicabilité](images/interface_explicabilite.png)

## 🚀 Installation et Lancement

Suivez ces étapes pour installer SentinelMail sur votre machine (Linux ou Windows).

### 1. Prérequis
- Python 3.10 ou plus récent
- Un compte Gmail avec un [Mot de passe d'application](https://myaccount.google.com/apppasswords)

### 2. Clonage du projet
```bash
git clone [https://github.com/tendoss/SentinelMail.git](https://github.com/tendoss/SentinelMail.git)
cd SentinelMail

## 🎮 Comment lancer SentinelMail ?

Une fois que vous avez installé les dépendances, vous pouvez lancer l'application de deux manières :

### Option 1 : La commande standard (Tous systèmes)
Ouvrez votre terminal dans le dossier du projet et tapez :
```bash
python3 main.py
