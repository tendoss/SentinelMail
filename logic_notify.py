"""
logic_notify.py — Module de notification WhatsApp pour SentinelMail (Phase 3)
=============================================================================
Permet d'alerter l'utilisateur en cas de menace critique (Score > 7).

Deux modes possibles :
  1. Automatique (API Twilio) : Nécessite un compte gratuit Twilio.
  2. Manuel (Web/Desktop) : Ouvre l'application WhatsApp avec le message prêt.
"""

import webbrowser
from urllib.parse import quote

class WhatsAppNotifier:
    def __init__(self, phone_number=None):
        """
        :param phone_number: Numéro au format international (ex: +243...)
        """
        self.phone_number = phone_number

    def send_alert_manual(self, score, subject):
        """Ouvre WhatsApp avec un message pré-rempli."""
        message = f"🛡️ *ALERTE SENTINELMAIL*\n\nUne menace critique a été détectée !\n🎯 *Score : {score}/10*\n📧 Objet : {subject}\n\nVeuillez vérifier votre centre de défense immédiatement."
        url = f"https://wa.me/{self.phone_number}?text={quote(message)}"
        webbrowser.open(url)

    def send_alert_auto(self, score, subject, account_sid, auth_token, to_whatsapp):
        """
        Envoie un message automatique via l'API Twilio Sandbox (Gratuit).
        Nécessite l'installation de 'twilio' : pip install twilio
        """
        if not account_sid or not auth_token or not to_whatsapp:
            return False, "Identifiants WhatsApp non configurés."
            
        try:
            from twilio.rest import Client
            client = Client(account_sid, auth_token)
            
            # Message formaté
            message_body = (
                f"🛡️ *SENTINELMAIL : ALERTE CRITIQUE*\n\n"
                f"Une menace à haut risque a été interceptée.\n\n"
                f"📊 *Score de danger : {score}/10*\n"
                f"📧 *Objet :* {subject}\n\n"
                f"⚠️ *Action :* Vérifiez votre centre de défense SentinelMail immédiatement."
            )
            
            # Utilisation du numéro Sandbox standard de Twilio
            message = client.messages.create(
                from_='whatsapp:+14155238886',
                body=message_body,
                to=f'whatsapp:{to_whatsapp}'
            )
            return True, message.sid
        except Exception as e:
            return False, str(e)
