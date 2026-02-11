#!/bin/bash

# 1. Obtenir le chemin actuel
APP_PATH=$(pwd)

# 2. Créer le dossier autostart s'il n'existe pas
mkdir -p ~/.config/autostart

# 3. Créer le fichier desktop
cat <<EOF > ~/.config/autostart/mailguard.desktop
[Desktop Entry]
Type=Application
Name=MailGuard
Exec=python3 $APP_PATH/main.py
Terminal=false
X-GNOME-Autostart-enabled=true
EOF

chmod +x ~/.config/autostart/mailguard.desktop

echo "L'application se lancera automatiquement au démarrage de Kali."
