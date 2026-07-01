import imapclient
import email
import joblib
import ssl
import re
import dns.resolver
import socket
import requests
import cv2 # Pour l'analyse d'image (QR Code)
import numpy as np # Pour transformer les bytes en image
from dateutil import parser
from urllib.parse import urlparse

# --- Modules de securite avancee (Phase 1 & 2) ---
from security_enhanced import EmailAuthChecker, AdvancedUrlChecker, AttachmentForensics

class MailAnalyzer:
    def __init__(self):
        try:
            self.model = joblib.load('model.joblib')
            self.vectorizer = joblib.load('vectorizer.joblib')
        except:
            self.model = None
        # Analyseurs avances (sans dependance payante)
        self.auth_checker = EmailAuthChecker()
        self.url_advanced = AdvancedUrlChecker()
        self.att_forensics = AttachmentForensics()

    def get_geolocation(self, domain):
        """Trouve le pays d'origine du serveur mail."""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_host = str(mx_records[0].exchange)
            ip_addr = socket.gethostbyname(mx_host)
            response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=2).json()
            if response['status'] == 'success':
                return f"{response['country']} ({response['city']})"
        except: pass
        return "Localisation Inconnue"

    def check_domain_dns(self, sender):
        try:
            domain = sender.split('@')[-1]
            dns.resolver.resolve(domain, 'MX')
            return 0, []
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return 2.5, ["❌ DNS [+2.5]: Domaine techniquement invalide (Pas de MX)"]
        except: return 0, []

    def analyze_urls(self, text, source="Corp du mail"):
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        score = 0
        details = []
        
        for url in urls:
            domain = urlparse(url).netloc.lower()
            if re.match(r'\d{1,3}\.\d{1,3}', domain): 
                score += 4
                details.append(f"🔗 URL ({source}) [+4.0]: Adresse IP directe ({domain})")
            
            if any(x in domain for x in ['secure', 'login', 'verify', 'update', 'banque']): 
                score += 2.5
                details.append(f"🔗 URL ({source}) [+2.5]: Mots pièges dans le lien")
                
            # Extension suspecte
            if domain.endswith(('.xyz', '.top', '.ru', '.cn')):
                score += 1.5
                details.append(f"🔗 URL ({source}) [+1.5]: Extension de domaine risquée")

        return score, len(urls), details

    def analyze_pdf_bytes(self, content_bytes):
        """Analyse binaire d'un PDF pour trouver des scripts malveillants."""
        score = 0
        details = []
        try:
            # On cherche des signatures textuelles de commandes dangereuses dans le binaire
            text_content = content_bytes.decode('latin-1', errors='ignore')
            
            dangerous_keywords = {
                '/JavaScript': 'Script exécutable (Virus potentiel)',
                '/JS': 'Script exécutable court',
                '/OpenAction': 'Action automatique à l\'ouverture',
                '/Launch': 'Tentative de lancement de programme externe'
            }
            
            for keyword, reason in dangerous_keywords.items():
                if keyword in text_content:
                    score += 5 # PÉNALITÉ MAXIMALE
                    details.append(f"📄 PDF DANGEREUX [+5.0]: Contient {keyword} ({reason})")
                    break # Une seule menace suffit pour alerter
        except: pass
        return score, details

    def analyze_qr_code(self, image_bytes):
        """Détecte et décode un QR Code dans une image."""
        score = 0
        details = []
        try:
            # Conversion bytes -> Image OpenCV
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img is not None:
                detector = cv2.QRCodeDetector()
                data, bbox, _ = detector.detectAndDecode(img)
                
                if data:
                    details.append(f"📱 QR Code Détecté : Contenu = {data[:30]}...")
                    # Si le QR code est une URL, on l'analyse
                    if data.startswith('http'):
                        url_score, _, url_details = self.analyze_urls(data, source="QR Code")
                        score += url_score + 1 # +1 juste pour la présence d'un QR code (technique de dissimulation)
                        if url_score > 0:
                            details.extend(url_details)
                        else:
                            details.append("📱 QR Code [+1.0]: Présence suspecte d'un lien QR")
        except: pass
        return score, details

    def get_score(self, text, subject, sender, attachments, auth_header=None):
        report = [] 
        domain = sender.split('@')[-1] if '@' in sender else ''
        
        # 1. Authentification (SPF/DKIM/DMARC) - NOUVEAU
        auth_score, auth_reasons = self.auth_checker.analyze(auth_header, domain)
        report.extend(auth_reasons)

        # 2. IA (Sémantique)
        ml_score = 0
        if self.model and self.vectorizer:
            try:
                vect = self.vectorizer.transform([text])
                ml_score = self.model.predict_proba(vect)[0][1] * 10
                if ml_score > 6:
                    report.append(f"🤖 IA [+{(ml_score*0.4):.1f}]: Vocabulaire typique du phishing détecté")
            except: ml_score = 0
            
        # 3. URLs (Corps du mail) - AMÉLIORÉ
        url_score, url_count, url_reasons = self.analyze_urls(text)
        report.extend(url_reasons)
        
        # Analyse URL avancée (homoglyphes, etc.) - NOUVEAU
        adv_url_score, _, adv_url_reasons = self.url_advanced.analyze(text)
        url_score += adv_url_score
        report.extend(adv_url_reasons)
        
        # 4. DNS
        dns_score, dns_reasons = self.check_domain_dns(sender)
        report.extend(dns_reasons)
        
        # 5. Pression Psychologique
        pression_score = 0
        mots_urgence = ['urgent', 'immédiatement', 'suspendu', '24h', 'bloqué', 'police', 'huissier']
        found_words = [w for w in mots_urgence if w in text.lower()]
        if found_words:
            pression_score = 2
            report.append(f"🧠 Pression [+2.0]: Mots coercitifs trouvés ({', '.join(found_words)})")

        # 6. Analyse des Pièces Jointes (PDF, QR & Forensics étendu)
        att_score = 0
        for filename, content_bytes in attachments:
            ext = filename.lower().split('.')[-1]
            
            # Forensics avancé (Office, HTML, exécutables) - NOUVEAU
            adv_att_s, adv_att_d = self.att_forensics.analyze(filename, content_bytes)
            att_score += adv_att_s
            report.extend(adv_att_d)

            # Analyse PDF (existant)
            if ext == 'pdf':
                pdf_s, pdf_d = self.analyze_pdf_bytes(content_bytes)
                att_score += pdf_s
                report.extend(pdf_d)
            
            # Analyse Image (QR Code) (existant)
            if ext in ['png', 'jpg', 'jpeg', 'bmp']:
                qr_s, qr_d = self.analyze_qr_code(content_bytes)
                att_score += qr_s
                report.extend(qr_d)

        # --- CALCUL FINAL ---
        # On inclut le auth_score dans le calcul final
        final_score = (ml_score * 0.4) + (min(url_score, 10) * 0.3) + (pression_score * 0.1) + dns_score + att_score + auth_score
        
        location = self.get_geolocation(domain)
        
        return round(min(final_score, 10), 2), location, report

class MailWorker:
    """Ancien worker IMAP (Legacy). Garde pour compatibilite ou autres services (Outlook/Yahoo)."""
    def __init__(self, host, user, password):
        self.host, self.user, self.password = host, user, password
        self.analyzer = MailAnalyzer()
        self.client = None

    def connect(self):
        context = ssl.create_default_context()
        self.client = imapclient.IMAPClient(self.host, ssl=True, ssl_context=context)
        self.client.login(self.user, self.password)
        self.client.select_folder('INBOX')

    def scan_all_emails(self):
        uids = self.client.search(['ALL'])[::-1][:15] # 15 derniers mails
        messages = self.client.fetch(uids, ['RFC822'])
        results = []
        
        for uid in uids:
            msg = email.message_from_bytes(messages[uid][b'RFC822'])
            sub = str(msg.get('Subject', 'Sans objet'))
            sender = str(msg.get('From', ''))
            sender_clean = re.search(r'<(.+?)>', sender)
            sender_email = sender_clean.group(1) if sender_clean else sender
            
            # Extraction Authentification (Authentication-Results)
            auth_header = msg.get('Authentication-Results', '')
            
            # Extraction Date
            raw_date = str(msg.get('Date', ''))
            try: date_fr = parser.parse(raw_date).strftime("%d/%m %H:%M")
            except: date_fr = raw_date
            
            # Extraction Corps et Pièces Jointes
            body = ""
            attachments = [] # Liste de tuples (nom_fichier, bytes)
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        body = part.get_payload(decode=True).decode(errors='ignore')
                    elif content_type == "text/html" and "attachment" not in content_disposition:
                        # On préfère le HTML pour l'analyse
                        body = part.get_payload(decode=True).decode(errors='ignore')
                    
                    # Détection pièce jointe
                    if part.get_filename():
                        payload = part.get_payload(decode=True)
                        if payload:
                            attachments.append((part.get_filename(), payload))
            else:
                body = msg.get_payload(decode=True).decode(errors='ignore')
            
            # ANALYSE COMPLETE
            score, loc, report = self.analyzer.get_score(body, sub, sender_email, attachments, auth_header=auth_header)
            
            results.append({
                "uid": uid, "sub": sub, "score": score, 
                "date": date_fr, "sender": sender, "location": loc, "report": report
            })
        return results

    def get_mail_content(self, uid):
        # Fonction simple pour l'affichage (inchangée)
        data = self.client.fetch([uid], ['RFC822'])
        msg = email.message_from_bytes(data[uid][b'RFC822'])
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    return part.get_payload(decode=True).decode(errors='ignore')
        else:
            return msg.get_payload(decode=True).decode(errors='ignore')
        return "(Contenu vide ou illisible)"
