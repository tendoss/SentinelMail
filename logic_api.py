"""
logic_api.py — Gestion de l'API Gmail et OAuth 2.0 pour SentinelMail (Phase 2)
==============================================================================
Remplace IMAP par l'API REST Google Mail.
Permet :
  1. Connexion via OAuth 2.0 (pas de mot de passe d'application)
  2. Analyse temps reel
  3. Recuperation propre du HTML et des images integrees (CID)
"""

import os
import base64
import json
import re
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Scopes requis pour lire et gerer les mails (pour la future remediation)
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

class GmailAPIWorker:
    def __init__(self, token_file='token.json', credentials_file='credentials.json'):
        self.token_file = token_file
        self.credentials_file = credentials_file
        self.creds = None
        self.service = None

    def authenticate(self):
        """Gere le flux OAuth 2.0."""
        if os.path.exists(self.token_file):
            self.creds = Credentials.from_authorized_user_file(self.token_file, SCOPES)
        
        # Si pas de credentials valides, on lance le navigateur
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                if not os.path.exists(self.credentials_file):
                    raise FileNotFoundError(f"Le fichier {self.credentials_file} est manquant. Veuillez le generer sur Google Cloud Console.")
                
                flow = InstalledAppFlow.from_client_secrets_file(self.credentials_file, SCOPES)
                self.creds = flow.run_local_server(port=0)
            
            # Sauvegarde du token pour la prochaine fois
            with open(self.token_file, 'w') as token:
                token.write(self.creds.to_json())

        self.service = build('gmail', 'v1', credentials=self.creds)
        return self.get_user_email()

    def get_user_email(self):
        """Recupere l'adresse mail de l'utilisateur connecte."""
        profile = self.service.users().getProfile(userId='me').execute()
        return profile.get('emailAddress')

    def list_messages(self, max_results=15):
        """Liste les derniers messages."""
        try:
            results = self.service.users().messages().list(userId='me', maxResults=max_results).execute()
            return results.get('messages', [])
        except HttpError as error:
            print(f'Erreur API Gmail: {error}')
            return []

    def get_message_details(self, msg_id):
        """Recupere le contenu complet d'un message par son ID."""
        return self.service.users().messages().get(userId='me', id=msg_id, format='full').execute()

    def parse_parts(self, parts, msg_id):
        """Parse recursivement les parties d'un mail pour extraire body et attachments."""
        body = ""
        html_body = ""
        attachments = [] # (filename, bytes, content_id)
        
        for part in parts:
            mime_type = part.get('mimeType')
            filename = part.get('filename')
            body_data = part.get('body', {}).get('data')
            content_id = ""
            
            # Recuperation du Content-ID pour les images integrees
            headers = part.get('headers', [])
            for h in headers:
                if h.get('name').lower() == 'content-id':
                    content_id = h.get('value').strip('<>')

            if mime_type == 'text/plain' and body_data:
                body += base64.urlsafe_b64decode(body_data).decode(errors='ignore')
            elif mime_type == 'text/html' and body_data:
                html_body += base64.urlsafe_b64decode(body_data).decode(errors='ignore')
            elif filename:
                # C'est une piece jointe ou une image integree
                att_id = part.get('body', {}).get('attachmentId')
                if att_id:
                    att_data = self.service.users().messages().attachments().get(
                        userId='me', messageId=msg_id, id=att_id).execute()
                    data = base64.urlsafe_b64decode(att_data.get('data'))
                    attachments.append((filename, data, content_id))
            
            if 'parts' in part:
                b, h, a = self.parse_parts(part['parts'], msg_id)
                body += b
                html_body += h
                attachments.extend(a)
                
        return body, html_body, attachments

    def process_message(self, msg_summary, analyzer):
        """Recupere, analyse et formate un message pour l'interface."""
        msg = self.get_message_details(msg_summary['id'])
        headers = msg.get('payload', {}).get('headers', [])
        
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'Sans objet')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
        date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
        auth_header = next((h['value'] for h in headers if h['name'].lower() == 'authentication-results'), '')
        
        # Nettoyage sender
        sender_clean = re.search(r'<(.+?)>', sender)
        sender_email = sender_clean.group(1) if sender_clean else sender

        # Extraction corps et pieces jointes
        payload = msg.get('payload', {})
        body_text = ""
        body_html = ""
        attachments = []

        if 'parts' in payload:
            body_text, body_html, attachments = self.parse_parts(payload['parts'], msg['id'])
        else:
            data = payload.get('body', {}).get('data')
            if data:
                body_text = base64.urlsafe_b64decode(data).decode(errors='ignore')
                body_html = body_text # fallback

        # Analyse
        # Note : On passe body_html a l'analyseur car il contient souvent plus d'info (liens caches)
        # Mais on utilise body_text pour le ML si possible.
        analysis_text = body_html if body_html else body_text
        score, loc, report = analyzer.get_score(analysis_text, subject, sender_email, 
                                               [(a[0], a[1]) for a in attachments], 
                                               auth_header=auth_header)
        
        return {
            "id": msg['id'],
            "sub": subject,
            "score": score,
            "date": date,
            "sender": sender,
            "location": loc,
            "report": report,
            "html": body_html if body_html else body_text.replace('\n', '<br>'),
            "attachments": attachments # Garde les (filename, bytes, cid) pour l'affichage des images
        }
