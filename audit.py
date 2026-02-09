"""
audit.py — Module d'Audit de Sécurité (SIEM-Compatible)
=========================================================
Responsabilités :
    - Journalisation horodatée de tous les événements de sécurité
    - Format structuré compatible SIEM (Splunk, ELK, QRadar)
    - Protection contre l'injection de logs (sanitization)
    - Rotation automatique des fichiers de log

Conformité : PCI-DSS v4.0 §10, ISO 27001 A.12.4
"""

import logging
import os
import socket
from logging.handlers import RotatingFileHandler

# ============================================================================
# CONFIGURATION
# ============================================================================

LOG_FILE = "secure_audit.log"
MAX_LOG_SIZE = 5 * 1024 * 1024   # 5 MiB par fichier
BACKUP_COUNT = 5                  # 5 fichiers de rotation

# Identifiants machine (pour corrélation SIEM multi-serveurs)
_HOSTNAME = socket.gethostname()
_PID = os.getpid()

# ============================================================================
# INITIALISATION DU LOGGER
# ============================================================================

_logger = logging.getLogger("SecureVaultAudit")
_logger.setLevel(logging.INFO)
_logger.propagate = False  # Pas de propagation au root logger

# Handler avec rotation automatique
_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=MAX_LOG_SIZE,
    backupCount=BACKUP_COUNT,
    encoding="utf-8",
)
_handler.setFormatter(logging.Formatter(
    fmt="%(asctime)s | %(levelname)s | HOST=%(hostname)s | PID=%(pid)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))

# Permissions restrictives sur le fichier de log (0640)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        pass
    os.chmod(LOG_FILE, 0o640)

_logger.addHandler(_handler)


# ============================================================================
# SANITIZATION ANTI-INJECTION
# ============================================================================

def _sanitize(value: str) -> str:
    """
    Neutralise les caractères dangereux pour la journalisation.

    Menaces couvertes :
        - Injection de nouvelles lignes (log forging / CRLF injection)
        - Caractères de contrôle ANSI (attaque terminal)
        - Séparateurs de champs ('|') pour éviter la confusion SIEM
    """
    return (
        value
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("|", "/")
        .replace("\x1b", "")  # Escape ANSI
        .replace("\x00", "")  # Null byte
    )


# ============================================================================
# API PUBLIQUE
# ============================================================================

def log_event(event_type: str, user_context: str, description: str):
    """
    Enregistre un événement de sécurité critique.

    Args:
        event_type:   Catégorie normalisée (AUTH_SUCCESS, AUTH_FAIL, DATA_READ,
                      DATA_WRITE, DATA_DELETE, REVOCATION, LOGOUT, SYSTEM, ERROR).
        user_context: Identifiant de l'acteur (ex: "Slot #2 (Rep. Tech + Resp. Jur)").
        description:  Détail de l'action (ex: "Master Key loaded in RAM").
    """
    clean_type = _sanitize(event_type)
    clean_user = _sanitize(user_context)
    clean_desc = _sanitize(description)

    log_message = f"[{clean_type}] USER={clean_user} | DESC={clean_desc}"

    _logger.info(
        log_message,
        extra={"hostname": _HOSTNAME, "pid": _PID},
    )
