import logging
import os
from datetime import datetime

# Configuration du logging
LOG_FILE = "secure_audit.log"

# On configure le format pour être lisible par une machine (pour le SIEM)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_event(event_type: str, user_context: str, description: str):
    """
    Enregistre un événement critique.
    
    Args:
        event_type (str): AUTH, ACCESS, REVOCATION, ERROR, SYSTEM
        user_context (str): Qui a fait l'action (ex: "Slot #2 (Rep. Tech + Resp. Jur)")
        description (str): Détail de l'action (ex: "Master Key loaded in RAM")
    """
    # On nettoie les entrées pour éviter l'injection de logs
    clean_desc = description.replace("\n", " ").replace("\r", " ")
    
    log_message = f"[{event_type}] USER={user_context} | DESC={clean_desc}"
    
    # Écriture disque + Affichage console
    logging.info(log_message)
