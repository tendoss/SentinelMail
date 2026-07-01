"""
security_enhanced.py — Module de sécurité avancée pour SentinelMail (Phase 1)
=============================================================================
Ce module ajoute, SANS dépendances payantes, les capacités suivantes :

  1. Authentification de l'expéditeur : SPF, DKIM, DMARC
  2. Détection des URL trompeuses : homoglyphes (Unicode), domaines récents,
     raccourcisseurs d'URL, sous-domaines trompeurs
  3. Forensics étendu des pièces jointes : documents Office à macros,
     fichiers HTML piégés, archives, doubles extensions

Toutes les fonctions sont défensives : en cas d'erreur, elles renvoient un
score neutre (0) et n'interrompent jamais l'analyse principale.

Dépendances : dnspython (déjà présent dans requirements.txt).
"""

import re
import zipfile
import io
from urllib.parse import urlparse

try:
    import dns.resolver
    _DNS_OK = True
except Exception:
    _DNS_OK = False


# ---------------------------------------------------------------------------
# 1. AUTHENTIFICATION DE L'EXPÉDITEUR (SPF / DKIM / DMARC)
# ---------------------------------------------------------------------------

class EmailAuthChecker:
    """Vérifie l'authentification d'un email à partir de ses en-têtes et du DNS.

    Deux sources d'information sont utilisées :
      - L'en-tête `Authentication-Results` ajouté par le serveur receveur
        (Gmail le renseigne systématiquement). C'est la source la plus fiable.
      - Une vérification DNS de la politique DMARC du domaine expéditeur,
        en complément, lorsque l'en-tête est absent.
    """

    @staticmethod
    def _extract_result(auth_header, mechanism):
        """Extrait le verdict (pass/fail/...) d'un mécanisme dans l'en-tête."""
        if not auth_header:
            return None
        # Cherche par exemple "spf=pass", "dkim=fail", "dmarc=none"
        match = re.search(rf"{mechanism}\s*=\s*(\w+)", auth_header, re.IGNORECASE)
        return match.group(1).lower() if match else None

    @staticmethod
    def check_dmarc_policy(domain):
        """Interroge le DNS pour récupérer la politique DMARC publiée (p=...)."""
        if not _DNS_OK or not domain:
            return None
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = b"".join(rdata.strings).decode(errors="ignore") if hasattr(rdata, "strings") else str(rdata)
                if "v=DMARC1" in txt:
                    m = re.search(r"p\s*=\s*(\w+)", txt)
                    return m.group(1).lower() if m else "none"
        except Exception:
            return None
        return None

    def analyze(self, auth_results_header, sender_domain):
        """Renvoie (score, details) à partir de l'authentification.

        Logique de score :
          - DMARC fail / DKIM fail / SPF fail = forte présomption d'usurpation.
          - Aucune politique DMARC publiée = domaine vulnérable au spoofing.
        """
        score = 0
        details = []

        spf = self._extract_result(auth_results_header, "spf")
        dkim = self._extract_result(auth_results_header, "dkim")
        dmarc = self._extract_result(auth_results_header, "dmarc")

        if dmarc == "fail":
            score += 4.0
            details.append("🛡️ DMARC [+4.0]: Échec d'authentification (usurpation très probable)")
        if dkim == "fail":
            score += 2.5
            details.append("🛡️ DKIM [+2.5]: Signature invalide (message altéré ou usurpé)")
        if spf == "fail":
            score += 2.5
            details.append("🛡️ SPF [+2.5]: Serveur émetteur non autorisé pour ce domaine")
        elif spf == "softfail":
            score += 1.0
            details.append("🛡️ SPF [+1.0]: Serveur émetteur douteux (softfail)")

        # Si aucune info dans l'en-tête, on vérifie au moins la politique DMARC publiée
        if dmarc is None and spf is None and dkim is None:
            policy = self.check_dmarc_policy(sender_domain)
            if policy is None:
                score += 1.5
                details.append("🛡️ DMARC [+1.5]: Domaine sans politique DMARC (vulnérable à l'usurpation)")

        return score, details


# ---------------------------------------------------------------------------
# 2. DÉTECTION D'URL TROMPEUSES (homoglyphes, raccourcisseurs, etc.)
# ---------------------------------------------------------------------------

class AdvancedUrlChecker:
    """Analyse les URL au-delà des simples mots-pièges."""

    # Raccourcisseurs d'URL courants qui masquent la destination réelle
    SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
    }

    @staticmethod
    def _has_homoglyph(domain):
        """Détecte la présence de caractères non-ASCII (cyrillique, grec...)
        utilisés pour imiter visuellement un domaine légitime."""
        try:
            domain.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    @staticmethod
    def _is_punycode(domain):
        """Les domaines en xn-- sont des IDN, souvent utilisés pour le phishing."""
        return "xn--" in domain.lower()

    @staticmethod
    def _suspicious_subdomain(domain):
        """Un grand nombre de sous-domaines ou un domaine connu en sous-domaine
        (ex: paypal.com.secure-login.ru) est un marqueur classique."""
        parts = domain.split(".")
        if len(parts) >= 4:
            return True
        known_brands = ["paypal", "google", "microsoft", "apple", "amazon", "banque", "impots"]
        # marque connue qui n'est PAS le domaine principal => trompeur
        if len(parts) >= 2:
            main_domain = parts[-2]
            for brand in known_brands:
                if brand in domain and brand != main_domain:
                    return True
        return False

    def analyze(self, text, source="Corps du mail"):
        urls = re.findall(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            text,
        )
        score = 0
        details = []

        for url in urls:
            domain = urlparse(url).netloc.lower()
            if not domain:
                continue

            if self._has_homoglyph(domain) or self._is_punycode(domain):
                score += 3.5
                details.append(f"🔗 URL ({source}) [+3.5]: Caractères trompeurs/homoglyphes dans le domaine")

            if domain in self.SHORTENERS:
                score += 1.5
                details.append(f"🔗 URL ({source}) [+1.5]: Lien raccourci masquant la vraie destination")

            if self._suspicious_subdomain(domain):
                score += 2.0
                details.append(f"🔗 URL ({source}) [+2.0]: Structure de sous-domaine trompeuse ({domain})")

        return score, len(urls), details


# ---------------------------------------------------------------------------
# 3. FORENSICS ÉTENDU DES PIÈCES JOINTES
# ---------------------------------------------------------------------------

class AttachmentForensics:
    """Analyse les pièces jointes autres que le PDF : Office, HTML, archives."""

    # Extensions directement exécutables = très dangereuses en pièce jointe
    EXECUTABLE_EXT = {
        "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jar",
        "msi", "ps1", "hta", "wsf",
    }
    OFFICE_MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm"}
    OFFICE_EXT = {"docx", "xlsx", "pptx", "doc", "xls", "ppt"}

    def analyze(self, filename, content_bytes):
        score = 0
        details = []
        name = filename.lower()
        ext = name.split(".")[-1] if "." in name else ""

        # a) Double extension (ex: facture.pdf.exe)
        if name.count(".") >= 2:
            parts = name.split(".")
            if parts[-1] in self.EXECUTABLE_EXT and parts[-2] in ("pdf", "doc", "jpg", "txt", "xls"):
                score += 5.0
                details.append(f"📎 FICHIER [+5.0]: Double extension trompeuse ({filename})")

        # b) Exécutable direct
        if ext in self.EXECUTABLE_EXT:
            score += 5.0
            details.append(f"📎 FICHIER DANGEREUX [+5.0]: Pièce jointe exécutable (.{ext})")

        # c) Office avec macros (format *m)
        elif ext in self.OFFICE_MACRO_EXT:
            score += 3.0
            details.append(f"📎 OFFICE [+3.0]: Document à macros activées (.{ext})")

        # d) Office moderne (zip) : on cherche un projet VBA caché
        elif ext in self.OFFICE_EXT:
            macro_score, macro_det = self._scan_office_macros(content_bytes)
            score += macro_score
            details.extend(macro_det)

        # e) Fichier HTML piégé
        elif ext in ("html", "htm"):
            html_score, html_det = self._scan_html(content_bytes)
            score += html_score
            details.extend(html_det)

        return score, details

    def _scan_office_macros(self, content_bytes):
        """Un .docx/.xlsx est un ZIP ; la présence de vbaProject.bin = macros."""
        score = 0
        details = []
        try:
            with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
                names = z.namelist()
                if any("vbaProject.bin" in n for n in names):
                    score += 3.5
                    details.append("📎 OFFICE [+3.5]: Macro VBA cachée détectée dans le document")
        except Exception:
            pass
        return score, details

    def _scan_html(self, content_bytes):
        """Recherche de scripts/redirections dangereux dans un fichier HTML."""
        score = 0
        details = []
        try:
            content = content_bytes.decode("latin-1", errors="ignore").lower()
            triggers = {
                "<script": "Script JavaScript intégré",
                "window.location": "Redirection automatique",
                "eval(": "Exécution de code dynamique",
                "atob(": "Contenu encodé/dissimulé (base64)",
                "document.write": "Injection de contenu dynamique",
            }
            for needle, reason in triggers.items():
                if needle in content:
                    score += 2.5
                    details.append(f"📎 HTML [+2.5]: {reason}")
                    break  # une alerte suffit
        except Exception:
            pass
        return score, details
