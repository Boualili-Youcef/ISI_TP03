import os
import json
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

# Configuration du RAM DISK
# Sous Linux, /dev/shm est monté en mémoire vive.
# Tout fichier écrit ici disparaît à l'extinction de la machine.
RAM_DISK_PATH = "/dev/shm/secure_server_key"

def derive_part(password: str, usb_key_path: str, salt: bytes) -> bytes:
    """
    Dérive une part de secret cryptographique en combinant un facteur de connaissance (Savoir)
    et un facteur de possession (Avoir).

    Standard de Sécurité : 
        - KDF : Argon2id (Recommandation OWASP/NIST).
        - Fusion : Opération XOR (Information Theoretic Security).

    Args:
        password (str): Le mot de passe en clair du responsable.
        usb_key_path (str): Le chemin absolu vers le fichier de clé (.bin).
        salt (bytes): Le sel cryptographique unique (16 bytes) associé au coffre.

    Returns:
        bytes: Une séquence de 32 octets représentant la part de clé dérivée.

    Raises:
        FileNotFoundError: Si le fichier de clé USB est absent.
        ValueError: Si le fichier USB est corrompu.
    """
    # Vérification du Facteur Physique (Ce que j'ai)
    if not os.path.exists(usb_key_path):
        raise FileNotFoundError(f"[AUDIT] ECHEC AUTH : Clé USB introuvable à {usb_key_path}")
    
    with open(usb_key_path, "rb") as f:
        usb_secret = f.read()
        if len(usb_secret) != 32:
            raise ValueError(f"[AUDIT] INTEGRITE : Fichier clé USB corrompu (Taille {len(usb_secret)} != 32)")

    # Traitement du Facteur Mémorable (Ce que je sais)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=4,
        memory_cost=65536,
    )
    pass_hash = kdf.derive(password.encode())

    # Fusion des facteurs (XOR)
    int_pass = int.from_bytes(pass_hash, "big")
    int_usb = int.from_bytes(usb_secret, "big")
    xor_result = int_pass ^ int_usb
    
    return xor_result.to_bytes(32, "big")

def get_master_key() -> bytes:
    """
    Récupère la MK depuis le RAM Disk sécurisé.
    
    Raises:
        PermissionError: Si le serveur n'a pas été initialisé (Clé absente de la RAM).
    """
    if not os.path.exists(RAM_DISK_PATH):
        raise PermissionError("[SECURITE] ACCES REFUSE : Serveur verrouillé. Veuillez effectuer la Mise en Service (1.i)")
    
    # Lecture depuis la RAM uniquement
    with open(RAM_DISK_PATH, "rb") as f:
        return f.read()

def save_database(data: dict, mk: bytes):
    """
    Chiffre et sauvegarde la DB sur le disque dur avec AES-256-GCM.
    Génère un nouveau Nonce à chaque écriture pour éviter les attaques par réutilisation d'IV.
    """
    aesgcm = AESGCM(mk)
    nonce = os.urandom(12) # Nonce unique indispensable pour GCM
    
    try:
        plaintext = json.dumps(data).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        with open("cards.db.enc", "wb") as f:
            # On stocke le nonce en clair (nécessaire pour déchiffrer) + le ciphertext
            f.write(nonce + ciphertext)
    except Exception as e:
        raise RuntimeError(f"[CRITIQUE] Erreur lors de l'écriture chiffrée : {e}")

def load_database(mk: bytes) -> dict:
    """
    Charge et déchiffre la DB depuis le disque dur.
    Vérifie l'intégrité des données grâce au tag GCM inclus dans le ciphertext.
    """
    if not os.path.exists("cards.db.enc"):
        return {} # Base vide par défaut
        
    with open("cards.db.enc", "rb") as f:
        content = f.read()
    
    # Extraction du Nonce (12 premiers octets) et du message chiffré
    nonce = content[:12]
    ciphertext = content[12:]
    
    aesgcm = AESGCM(mk)
    try:
        # Le decrypt vérifie automatiquement l'intégrité (Tag Auth)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))
    except Exception:
        raise ValueError("[SECURITE] ALERTE INTEGRITE : Échec du déchiffrement (Clé incorrecte ou fichier altéré).")
    
def secure_wipe_ram():
    """Écrase la clé en RAM avec du bruit avant de supprimer le fichier"""
    if os.path.exists(RAM_DISK_PATH):
        # 1. Écrasement (Shredding)
        file_size = os.path.getsize(RAM_DISK_PATH)
        with open(RAM_DISK_PATH, "wb") as f:
            f.write(os.urandom(file_size))
        
        # 2. Suppression
        os.remove(RAM_DISK_PATH)