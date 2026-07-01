"""
vault.py — Coffre-fort de mots de passe pour SentinelMail
=========================================================
Remplace le stockage en clair (.pwds.json) par une solution sécurisée.

Stratégie en deux niveaux :
  1. PRIORITÉ : le trousseau natif du système d'exploitation via `keyring`
     (Keychain macOS, Credential Manager Windows, Secret Service Linux).
     Les mots de passe ne touchent jamais le disque en clair.
  2. REPLI : si `keyring` n'est pas installé, chiffrement local AES (Fernet)
     avec une clé stockée dans un fichier à permissions restreintes.

L'interface publique reste identique à l'ancien AuthManager :
    save_password(user, pwd) / get_password(user) / delete_password(user)
afin de minimiser les changements dans main.py.
"""

import os
import json
import base64
import hashlib

SERVICE_NAME = "SentinelMail"

# --- Tentative d'utilisation du trousseau natif (méthode recommandée) -------
try:
    import keyring
    _KEYRING_OK = True
except Exception:
    _KEYRING_OK = False

# --- Repli chiffré local si keyring indisponible ----------------------------
try:
    from cryptography.fernet import Fernet
    _FERNET_OK = True
except Exception:
    _FERNET_OK = False


class SecureVault:
    KEY_FILE = ".vault_key"
    ENC_FILE = ".vault_store"

    # -- API publique --------------------------------------------------------
    @classmethod
    def save_password(cls, user, pwd):
        if _KEYRING_OK:
            keyring.set_password(SERVICE_NAME, user, pwd)
            return
        cls._fallback_save(user, pwd)

    @classmethod
    def get_password(cls, user):
        if _KEYRING_OK:
            try:
                return keyring.get_password(SERVICE_NAME, user)
            except Exception:
                return None
        return cls._fallback_get(user)

    @classmethod
    def delete_password(cls, user):
        if _KEYRING_OK:
            try:
                keyring.delete_password(SERVICE_NAME, user)
            except Exception:
                pass
            return
        cls._fallback_delete(user)

    # -- Repli chiffré local -------------------------------------------------
    @classmethod
    def _get_key(cls):
        """Génère/charge une clé de chiffrement locale (mode repli uniquement)."""
        if os.path.exists(cls.KEY_FILE):
            with open(cls.KEY_FILE, "rb") as f:
                return f.read()
        if _FERNET_OK:
            key = Fernet.generate_key()
        else:
            # Dernier recours : clé dérivée (XOR), bien moins robuste mais
            # évite le stockage en clair complet.
            key = base64.urlsafe_b64encode(hashlib.sha256(os.urandom(32)).digest())
        with open(cls.KEY_FILE, "wb") as f:
            f.write(key)
        try:
            os.chmod(cls.KEY_FILE, 0o600)  # lecture seule par le propriétaire
        except Exception:
            pass
        return key

    @classmethod
    def _load_store(cls):
        if not os.path.exists(cls.ENC_FILE):
            return {}
        try:
            with open(cls.ENC_FILE, "rb") as f:
                blob = f.read()
            if _FERNET_OK:
                data = Fernet(cls._get_key()).decrypt(blob)
                return json.loads(data.decode())
            else:
                return json.loads(cls._xor(blob, cls._get_key()).decode())
        except Exception:
            return {}

    @classmethod
    def _write_store(cls, store):
        raw = json.dumps(store).encode()
        if _FERNET_OK:
            blob = Fernet(cls._get_key()).encrypt(raw)
        else:
            blob = cls._xor(raw, cls._get_key())
        with open(cls.ENC_FILE, "wb") as f:
            f.write(blob)
        try:
            os.chmod(cls.ENC_FILE, 0o600)
        except Exception:
            pass

    @classmethod
    def _fallback_save(cls, user, pwd):
        store = cls._load_store()
        store[user] = pwd
        cls._write_store(store)

    @classmethod
    def _fallback_get(cls, user):
        return cls._load_store().get(user)

    @classmethod
    def _fallback_delete(cls, user):
        store = cls._load_store()
        if user in store:
            del store[user]
            cls._write_store(store)

    @staticmethod
    def _xor(data, key):
        """Chiffrement XOR de dernier recours (si cryptography absent)."""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    # -- Migration depuis l'ancien fichier en clair --------------------------
    @classmethod
    def migrate_from_plaintext(cls):
        """Phase 2 : Importe et SUPPRIME tous les fichiers JSON de mots de passe en clair detectes."""
        files_to_clean = [".pwds.json", "accounts_passwords.json", "secrets.json"]
        count = 0
        for filename in files_to_clean:
            if os.path.exists(filename):
                try:
                    with open(filename, "r") as f:
                        data = json.load(f)
                    # Si c'est un dictionnaire user:pwd, on migre
                    if isinstance(data, dict):
                        for user, pwd in data.items():
                            cls.save_password(user, pwd)
                            count += 1
                    # On supprime systematiquement le fichier pour securiser le disque
                    os.remove(filename)
                except Exception as e:
                    print(f"⚠️ Impossible de nettoyer {filename}: {e}")
        return count


def backend_name():
    """Retourne le nom du backend actif (utile pour l'affichage/log)."""
    if _KEYRING_OK:
        return "Trousseau système (keyring)"
    if _FERNET_OK:
        return "Chiffrement local AES (Fernet)"
    return "Chiffrement local XOR (repli minimal)"
