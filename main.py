import sys, json, os, webbrowser
from PySide6.QtWidgets import *
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon
from logic import MailWorker, MailAnalyzer
from logic_api import GmailAPIWorker
from logic_notify import WhatsAppNotifier
from vault import SecureVault
import base64

class AuthManager:
    DB_FILE = "accounts.json"
    CONFIG_FILE = "config_notify.json"
    
    @classmethod
    def save_notify_config(cls, sid, token, phone):
        config = {"sid": sid, "token": token, "phone": phone}
        with open(cls.CONFIG_FILE, "w") as f: json.dump(config, f)
        
    @classmethod
    def get_notify_config(cls):
        if os.path.exists(cls.CONFIG_FILE):
            try:
                with open(cls.CONFIG_FILE, "r") as f: return json.load(f)
            except: return {}
        return {}

    @classmethod
    def save_account(cls, user, pwd):
        accounts = cls.get_accounts()
        if user not in accounts:
            accounts.append(user)
            with open(cls.DB_FILE, "w") as f: json.dump(accounts, f)
        # Utilisation du coffre-fort securise
        SecureVault.save_password(user, pwd)

    @classmethod
    def get_accounts(cls):
        if os.path.exists(cls.DB_FILE):
            try:
                with open(cls.DB_FILE, "r") as f: return json.load(f)
            except: return []
        return []

    @classmethod
    def get_pwd(cls, user):
        # Recuperation depuis le coffre-fort
        return SecureVault.get_password(user)

    @classmethod
    def delete_account(cls, user):
        accounts = cls.get_accounts()
        if user in accounts:
            accounts.remove(user)
            with open(cls.DB_FILE, "w") as f: json.dump(accounts, f)
        # Suppression dans le coffre-fort
        SecureVault.delete_password(user)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SentinelMail ULTIMATE - GeoTracking & Explainability")
        self.resize(1280, 850)
        self.setStyleSheet("""
            QMainWindow { background-color: #0F172A; }
            QLabel { color: #E2E8F0; font-family: 'Segoe UI', sans-serif; }
            QLineEdit, QComboBox { background-color: #1E293B; color: white; border: 2px solid #334155; border-radius: 8px; padding: 10px; }
            QPushButton { background-color: #38BDF8; color: #0F172A; border-radius: 8px; padding: 12px; font-weight: bold; }
            QPushButton:hover { background-color: #0EA5E9; }
            QListWidget { background-color: #1E293B; border: 1px solid #334155; color: #E2E8F0; border-radius: 10px; font-size: 13px; }
            QListWidget::item:selected { background-color: #334155; color: #38BDF8; }
            QTextBrowser { background-color: #FFFFFF; border-radius: 10px; border: 2px solid #334155; }
        """)
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.init_login_ui()
        self.init_dashboard_ui()
        self.current_report = [] # Stocke les explications du mail sélectionné

    def init_login_ui(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignCenter)
        
        title = QLabel("🛡️ SENTINEL MAIL")
        title.setStyleSheet("font-size: 50px; font-weight: 800; color: #38BDF8; margin-bottom: 10px;")
        subtitle = QLabel("PROTECTION AVANCÉE • TEMPS RÉEL • WHATSAPP")
        subtitle.setStyleSheet("font-size: 16px; color: #94A3B8; letter-spacing: 4px; margin-bottom: 40px;")
        
        card = QWidget()
        card.setFixedWidth(450)
        card.setStyleSheet("background-color: #1E293B; border-radius: 24px; padding: 30px; border: 1px solid #334155;")
        card_layout = QVBoxLayout(card)

        btn_google = QPushButton("🔵 CONTINUER AVEC GOOGLE")
        btn_google.setStyleSheet("""
            QPushButton { 
                background-color: #FFFFFF; color: #1F2937; border: 1px solid #D1D5DB; 
                font-size: 15px; padding: 15px; border-radius: 12px; font-weight: 600;
            }
            QPushButton:hover { background-color: #F9FAFB; border-color: #9CA3AF; }
        """)
        btn_google.clicked.connect(self.do_google_login)
        
        sep = QLabel("OU")
        sep.setStyleSheet("color: #64748B; font-size: 12px; font-weight: bold; margin: 20px 0;")
        sep.setAlignment(Qt.AlignCenter)

        btn_create = QPushButton("👤 CRÉER UN COMPTE LOCAL")
        btn_create.setStyleSheet("""
            QPushButton { 
                background-color: #38BDF8; color: #0F172A; font-size: 15px; 
                padding: 15px; border-radius: 12px; font-weight: 600;
            }
            QPushButton:hover { background-color: #0EA5E9; }
        """)
        btn_create.clicked.connect(self.show_create_account_dialog)

        card_layout.addWidget(btn_google)
        card_layout.addWidget(sep)
        card_layout.addWidget(btn_create)
        
        layout.addWidget(title, alignment=Qt.AlignCenter)
        layout.addWidget(subtitle, alignment=Qt.AlignCenter)
        layout.addWidget(card, alignment=Qt.AlignCenter)
        self.stack.addWidget(page)

    def show_create_account_dialog(self):
        """Affiche un dialogue simple pour créer un compte local (Phase 3)."""
        email, ok = QInputDialog.getText(self, "Créer un compte local", "Entrez votre adresse email :")
        if ok and email:
            QMessageBox.information(self, "Succès", f"Compte local créé pour {email}.\nVous pouvez maintenant vous connecter avec Google pour lier votre boîte.")

    def show_config_dialog(self):
        """Dialogue de configuration WhatsApp / Twilio."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Configuration WhatsApp Automatique")
        dialog.setFixedWidth(400)
        layout = QVBoxLayout(dialog)
        
        config = AuthManager.get_notify_config()
        
        layout.addWidget(QLabel("<b>Paramètres Twilio (WhatsApp)</b>"))
        sid_input = QLineEdit(config.get("sid", ""))
        sid_input.setPlaceholderText("Twilio Account SID")
        token_input = QLineEdit(config.get("token", ""))
        token_input.setPlaceholderText("Twilio Auth Token")
        token_input.setEchoMode(QLineEdit.Password)
        phone_input = QLineEdit(config.get("phone", ""))
        phone_input.setPlaceholderText("Votre numéro (ex: +243...)")
        
        layout.addWidget(QLabel("SID :"))
        layout.addWidget(sid_input)
        layout.addWidget(QLabel("Token :"))
        layout.addWidget(token_input)
        layout.addWidget(QLabel("Votre numéro WhatsApp :"))
        layout.addWidget(phone_input)
        
        help_text = QLabel("<small>Note : Utilisez le 'Sandbox' Twilio pour tester gratuitement.</small>")
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        
        btn_save = QPushButton("Enregistrer la configuration")
        btn_save.clicked.connect(lambda: [
            AuthManager.save_notify_config(sid_input.text(), token_input.text(), phone_input.text()),
            dialog.accept(),
            QMessageBox.information(self, "Succès", "Configuration WhatsApp enregistrée !")
        ])
        layout.addWidget(btn_save)
        dialog.exec()

    def auto_fill(self, user):
        p = AuthManager.get_pwd(user.strip())
        if p: self.pwd_input.setText(p)

    def init_dashboard_ui(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        
        # GAUCHE : LISTES DE MAILS
        left = QVBoxLayout()
        header_left = QHBoxLayout()
        self.welcome = QLabel("Session Active")
        self.welcome.setStyleSheet("font-size: 18px; font-weight: bold; color: #38BDF8;")
        
        btn_config = QPushButton("⚙️")
        btn_config.setFixedSize(30, 30)
        btn_config.setStyleSheet("background-color: #334155; color: white; border-radius: 15px;")
        btn_config.clicked.connect(self.show_config_dialog)
        
        header_left.addWidget(self.welcome)
        header_left.addWidget(btn_config)
        
        left.addLayout(header_left)
        
        # Panneau Critique (Score > 7)
        crit_label = QLabel("🔴 ALERTES CRITIQUES (Score > 7)")
        crit_label.setStyleSheet("font-weight: bold; color: #EF4444; font-size: 12px; margin-top: 10px;")
        self.crit_mail_list = QListWidget()
        self.crit_mail_list.setStyleSheet("border: 2px solid #EF4444; background-color: #1E1B1B;")
        self.crit_mail_list.itemClicked.connect(self.show_mail)
        
        # Panneau Normal
        norm_label = QLabel("🟢 AUTRES MESSAGES")
        norm_label.setStyleSheet("font-weight: bold; color: #10B981; font-size: 12px; margin-top: 10px;")
        self.norm_mail_list = QListWidget()
        self.norm_mail_list.itemClicked.connect(self.show_mail)
        
        btn_re = QPushButton("🔄 SCANNER LES MENACES")
        btn_re.clicked.connect(self.start_scan)
        btn_logout = QPushButton("DÉCONNEXION")
        btn_logout.setStyleSheet("background-color: #EF4444; color: white;")
        btn_logout.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        
        left.addWidget(self.welcome)
        left.addWidget(crit_label); left.addWidget(self.crit_mail_list)
        left.addWidget(norm_label); left.addWidget(self.norm_mail_list)
        left.addWidget(btn_re); left.addWidget(btn_logout)

        # DROITE : CONTENU
        right = QVBoxLayout()
        header_layout = QHBoxLayout()
        self.info_lab = QLabel("En attente...")
        self.info_lab.setStyleSheet("font-size: 16px; color: #94A3B8;")
        
        # BOUTON "INSPECTER"
        self.btn_inspect = QPushButton("🔍 INSPECTER CE MAIL")
        self.btn_inspect.setStyleSheet("background-color: #8B5CF6; color: white;")
        self.btn_inspect.setVisible(False)
        self.btn_inspect.clicked.connect(self.show_details_popup)
        
        header_layout.addWidget(self.info_lab)
        header_layout.addWidget(self.btn_inspect)

        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(False)
        self.browser.anchorClicked.connect(lambda url: webbrowser.open(url.toString()))
        
        right.addLayout(header_layout)
        right.addWidget(self.browser)
        
        layout.addLayout(left, 35); layout.addLayout(right, 65)
        self.stack.addWidget(page)

    def do_google_login(self):
        """Flux de connexion API Gmail OAuth 2.0 (Phase 2)."""
        try:
            self.api_worker = GmailAPIWorker()
            email_addr = self.api_worker.authenticate()
            self.analyzer = MailAnalyzer()
            self.is_api_mode = True
            self.welcome.setText(f"👤 {email_addr} (API)")
            self.stack.setCurrentIndex(1)
            self.start_scan()
        except Exception as e:
            QMessageBox.critical(self, "Erreur OAuth", f"Impossible de se connecter : {e}")

    def do_login(self):
        """Flux de connexion IMAP Legacy."""
        u = self.acc_select.currentText().strip(); p = self.pwd_input.text().strip()
        if not u or not p: return
        try:
            self.worker = MailWorker("imap.gmail.com", u, p)
            self.worker.connect()
            self.is_api_mode = False
            AuthManager.save_account(u, p)
            self.welcome.setText(f"👤 {u} (IMAP)")
            self.stack.setCurrentIndex(1)
            self.start_scan()
        except Exception as e: QMessageBox.critical(self, "Erreur IMAP", str(e))

    def do_delete(self):
        u = self.acc_select.currentText().strip()
        AuthManager.delete_account(u)
        self.acc_select.clear(); self.acc_select.addItems(AuthManager.get_accounts())

    def start_scan(self):
        self.crit_mail_list.clear()
        self.norm_mail_list.clear()
        self.norm_mail_list.addItem("📡 Analyse en temps réel (IA & Forensics)...")
        QApplication.processEvents()
        
        try:
            if self.is_api_mode:
                msg_list = self.api_worker.list_messages()
                mails = [self.api_worker.process_message(m, self.analyzer) for m in msg_list]
            else:
                mails = self.worker.scan_all_emails()
                
            self.crit_mail_list.clear()
            self.norm_mail_list.clear()
            
            # Récupération de la config WhatsApp
            config = AuthManager.get_notify_config()
            notifier = WhatsAppNotifier(phone_number=config.get("phone"))
            
            for m in mails:
                icon = "🔴" if m['score']>=7 else "🟠" if m['score']>=3 else "🟢"
                text = f"{icon} [{m['score']}/10] {m['sub']}\n    🌍 {m['location']} | 👤 {m['sender']}"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, m)
                
                # Tri des messages
                if m['score'] >= 7:
                    self.crit_mail_list.addItem(item)
                    # ALERTE WHATSAPP AUTOMATIQUE (Phase 3+)
                    if m == mails[0] and config.get("sid"): 
                        success, info = notifier.send_alert_auto(
                            m['score'], m['sub'], 
                            config["sid"], config["token"], config["phone"]
                        )
                        if not success:
                            print(f"⚠️ Échec envoi WhatsApp : {info}")
                else:
                    self.norm_mail_list.addItem(item)
                    
        except Exception as e: 
            self.norm_mail_list.addItem(f"Erreur: {e}")

    def show_mail(self, item):
        data = item.data(Qt.UserRole)
        if not data: return
        self.info_lab.setText(f"📅 {data['date']} | 🌍 {data['location']}")
        self.current_report = data['report']
        self.btn_inspect.setVisible(True)
        
        try:
            if self.is_api_mode:
                html = data['html']
                # --- Traitement des images integrees (CID) pour affichage haute fidelite ---
                for filename, content_bytes, cid in data.get('attachments', []):
                    if cid and cid in html:
                        b64_data = base64.b64encode(content_bytes).decode()
                        mime = "image/png" # fallback
                        if filename.lower().endswith('.jpg') or filename.lower().endswith('.jpeg'): mime = "image/jpeg"
                        elif filename.lower().endswith('.gif'): mime = "image/gif"
                        
                        # Remplacement du src="cid:..." par data:image/...;base64,...
                        html = html.replace(f'src="cid:{cid}"', f'src="data:{mime};base64,{b64_data}"')
                        html = html.replace(f"src='cid:{cid}'", f"src='data:{mime};base64,{b64_data}'")
                
                # Ajout d'un style de base pour le rendu propre
                styled_html = f"""
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #1F2937; background-color: white; }}
                    img {{ max-width: 100%; height: auto; border-radius: 4px; }}
                    a {{ color: #38BDF8; text-decoration: none; }}
                </style>
                {html}
                """
                self.browser.setHtml(styled_html)
            else:
                content = self.worker.get_mail_content(data['uid'])
                self.browser.setHtml(content)
        except Exception as e: 
            self.browser.setText(f"Erreur d'affichage : {e}")


    def show_details_popup(self):
        """Affiche la fenêtre d'explication détaillée"""
        if not self.current_report:
            QMessageBox.information(self, "Analyse Terminée", "✅ Aucun indicateur malveillant détecté.\nScore : 0/10")
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("🕵️ Rapport d'Investigation SentinelMail")
        
        # Titre stylé
        msg.setText("<h3 style='color:#38BDF8;'>🔍 POURQUOI CE SCORE ?</h3>")
        
        # Construction de la liste HTML
        details_html = "<ul style='margin-top:10px;'>"
        for reason in self.current_report:
            # Nettoyage des caractères et mise en gras du score
            clean_reason = reason.replace("[", "<b>[").replace("]", "]</b>")
            
            # Sélection de l'icône selon le contenu de la raison
            icon = "⚠️"
            if "DNS" in reason: icon = "🌐"
            elif "PDF" in reason: icon = "📄"
            elif "QR" in reason: icon = "📱"
            elif "URL" in reason: icon = "🔗"
            elif "IA" in reason: icon = "🤖"
            elif "Pression" in reason: icon = "🧠"
            
            details_html += f"<li style='font-size:13px; padding-bottom:5px;'>{icon} {clean_reason}</li>"
        details_html += "</ul>"
        
        msg.setInformativeText(details_html)
        msg.setIcon(QMessageBox.Warning)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec()
 	
if __name__ == "__main__":
    # Migration automatique des anciens mots de passe en clair (Phase 1)
    migrated = SecureVault.migrate_from_plaintext()
    if migrated > 0:
        print(f"✅ Securite : {migrated} compte(s) migre(s) vers le coffre-fort.")
        
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
