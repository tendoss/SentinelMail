import sys, json, os, webbrowser
from PySide6.QtWidgets import *
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon
from logic import MailWorker

class AuthManager:
    DB_FILE = "accounts.json"
    PWD_FILE = ".pwds.json"
    @classmethod
    def save_account(cls, user, pwd):
        accounts = cls.get_accounts()
        if user not in accounts:
            accounts.append(user)
            with open(cls.DB_FILE, "w") as f: json.dump(accounts, f)
        pwds = cls.get_all_pwds()
        pwds[user] = pwd
        with open(cls.PWD_FILE, "w") as f: json.dump(pwds, f)
    @classmethod
    def get_accounts(cls):
        if os.path.exists(cls.DB_FILE):
            try:
                with open(cls.DB_FILE, "r") as f: return json.load(f)
            except: return []
        return []
    @classmethod
    def get_all_pwds(cls):
        if os.path.exists(cls.PWD_FILE):
            try:
                with open(cls.PWD_FILE, "r") as f: return json.load(f)
            except: return {}
        return {}
    @classmethod
    def get_pwd(cls, user): return cls.get_all_pwds().get(user)
    @classmethod
    def delete_account(cls, user):
        accounts = cls.get_accounts()
        if user in accounts:
            accounts.remove(user)
            with open(cls.DB_FILE, "w") as f: json.dump(accounts, f)
        pwds = cls.get_all_pwds()
        if user in pwds:
            del pwds[user]
            with open(cls.PWD_FILE, "w") as f: json.dump(pwds, f)

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
        subtitle = QLabel("INTELLIGENCE ARTIFICIELLE • GÉOLOCALISATION • DNS")
        subtitle.setStyleSheet("font-size: 16px; color: #94A3B8; letter-spacing: 4px; margin-bottom: 40px;")
        
        card = QWidget()
        card.setFixedWidth(450)
        card.setStyleSheet("background-color: #1E293B; border-radius: 20px; padding: 20px;")
        card_layout = QVBoxLayout(card)

        self.acc_select = QComboBox()
        self.acc_select.setEditable(True)
        self.acc_select.addItems(AuthManager.get_accounts())
        self.acc_select.currentTextChanged.connect(self.auto_fill)
        self.pwd_input = QLineEdit()
        self.pwd_input.setPlaceholderText("Mot de passe d'application")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        btn_conn = QPushButton("OUVRIR LE CENTRE DE DÉFENSE")
        btn_conn.clicked.connect(self.do_login)
        btn_del = QPushButton("Oublier ce compte")
        btn_del.setStyleSheet("background-color: transparent; color: #EF4444; border: 1px solid #EF4444;")
        btn_del.clicked.connect(self.do_delete)

        card_layout.addWidget(self.acc_select)
        card_layout.addWidget(self.pwd_input)
        card_layout.addSpacing(20)
        card_layout.addWidget(btn_conn)
        card_layout.addWidget(btn_del)
        layout.addWidget(title, alignment=Qt.AlignCenter)
        layout.addWidget(subtitle, alignment=Qt.AlignCenter)
        layout.addWidget(card, alignment=Qt.AlignCenter)
        self.stack.addWidget(page)

    def auto_fill(self, user):
        p = AuthManager.get_pwd(user.strip())
        if p: self.pwd_input.setText(p)

    def init_dashboard_ui(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        
        # GAUCHE
        left = QVBoxLayout()
        self.welcome = QLabel("Session Active")
        self.welcome.setStyleSheet("font-size: 20px; font-weight: bold; color: #38BDF8;")
        self.mail_list = QListWidget()
        self.mail_list.itemClicked.connect(self.show_mail)
        btn_re = QPushButton("SCANNER LES MENACES")
        btn_re.clicked.connect(self.start_scan)
        btn_logout = QPushButton("DÉCONNEXION")
        btn_logout.setStyleSheet("background-color: #EF4444; color: white;")
        btn_logout.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        left.addWidget(self.welcome); left.addWidget(self.mail_list); left.addWidget(btn_re); left.addWidget(btn_logout)

        # DROITE
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

    def do_login(self):
        u = self.acc_select.currentText().strip(); p = self.pwd_input.text().strip()
        if not u or not p: return
        try:
            self.worker = MailWorker("imap.gmail.com", u, p)
            self.worker.connect()
            AuthManager.save_account(u, p)
            self.welcome.setText(f"👤 {u}")
            self.stack.setCurrentIndex(1)
            self.start_scan()
        except Exception as e: QMessageBox.critical(self, "Erreur", str(e))

    def do_delete(self):
        u = self.acc_select.currentText().strip()
        AuthManager.delete_account(u)
        self.acc_select.clear(); self.acc_select.addItems(AuthManager.get_accounts())

    def start_scan(self):
        self.mail_list.clear(); self.mail_list.addItem("📡 Tracking Géographique & Analyse IA...")
        QApplication.processEvents()
        try:
            mails = self.worker.scan_all_emails()
            self.mail_list.clear()
            for m in mails:
                icon = "🔴" if m['score']>=6 else "🟠" if m['score']>=3 else "🟢"
                # On affiche le pays dans la liste directement !
                text = f"{icon} [{m['score']}/10] {m['sub']}\n    🌍 {m['location']} | 👤 {m['sender']}"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, m) # On stocke tout l'objet dictionnaire
                self.mail_list.addItem(item)
        except Exception as e: self.mail_list.addItem(f"Erreur: {e}")

    def show_mail(self, item):
        data = item.data(Qt.UserRole)
        if not data: return
        # Mise à jour des infos
        self.info_lab.setText(f"📅 {data['date']} | 🌍 {data['location']}")
        
        # On sauvegarde le rapport pour le bouton "Inspecter"
        self.current_report = data['report']
        self.btn_inspect.setVisible(True) # On affiche le bouton
        
        # Affichage du contenu
        try:
            content = self.worker.get_mail_content(data['uid'])
            body_html = content.replace('\n', '<br>')
            html = f"<div style='color:#333; padding:10px;'>{body_html}</div>"
            self.browser.setHtml(html)
        except: self.browser.setText("Erreur lecture.")


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
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
