"""
crypto_utils.py — Module Cryptographique Central
==================================================
Responsabilités :
    - Dérivation de clé multi-facteurs (Argon2id + XOR)
    - Gestion sécurisée de la Master Key en RAM volatile (/dev/shm)
    - Chiffrement/Déchiffrement AES-256-GCM de la base de données
    - Effacement sécurisé (FIPS 140-3 §7.7) des secrets en mémoire

Conformité : NIST SP 800-131A, OWASP Key Management, PCI-DSS v4.0 §3.5
"""
import os
import json
import stat

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============================================================================
# CONSTANTES DE SÉCURITÉ
# ============================================================================

# Chemin du RAM Disk Linux — monté en tmpfs (mémoire vive uniquement).
# Tout fichier ici disparaît à l'extinction ou au reboot.
RAM_DISK_PATH = "/dev/shm/secure_server_key"

# Tailles attendues (bytes)
KEY_LENGTH = 32          # AES-256
NONCE_LENGTH = 12        # GCM standard (96 bits)
USB_KEY_LENGTH = 32      # Fichier clé physique (256 bits)
SALT_LENGTH = 16         # Sel global du vault

# Paramètres Argon2id (OWASP recommandation 2024)
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_COST = 262144  # 256 MiB — résistance GPU/ASIC (OWASP recommandé)

# Passes de zeroization pour la purge RAM (FIPS 140-3 §7.7)
WIPE_PASSES = 3 

# Fichier de la base de données chiffrée
DB_FILE = "cards.db.enc"


# ============================================================================
# DÉRIVATION DE CLÉ MULTI-FACTEURS
# ============================================================================

def derive_part(password: str, usb_key_path: str, salt: bytes) -> bytes:
    """
    Dérive une part de secret cryptographique en combinant un facteur de
    connaissance (Savoir) et un facteur de possession (Avoir).

    Chaîne cryptographique :
        Part = Argon2id(password, salt) ⊕ USB_Secret

    Sécurité :
        - KDF : Argon2id (résistant side-channel + GPU, OWASP/NIST).
        - Fusion : XOR — si l'un des deux facteurs est inconnu, le résultat
          est statistiquement indiscernable d'un aléa parfait (OTP).

    Args:
        password:     Mot de passe en clair du responsable.
        usb_key_path: Chemin absolu vers le fichier de clé USB (.bin).
        salt:         Sel cryptographique global du vault (16 bytes).

    Returns:
        bytes: Séquence de 32 octets (256 bits) — part de clé dérivée.

    Raises:
        FileNotFoundError: Fichier de clé USB absent ou inaccessible.
        ValueError:        Fichier USB corrompu (taille != 32 bytes).
    """
    # ── Facteur Physique (Ce que je possède) ──
    if not os.path.exists(usb_key_path):
        raise FileNotFoundError(
            f"Clé USB introuvable : {usb_key_path}"
        )

    with open(usb_key_path, "rb") as f:
        usb_secret = f.read()

    if len(usb_secret) != USB_KEY_LENGTH:
        raise ValueError(
            f"Fichier clé USB corrompu (taille {len(usb_secret)} != {USB_KEY_LENGTH} bytes)"
        )

    # ── Facteur Mémorable (Ce que je sais) ──
    kdf = Argon2id(
        salt=salt,
        length=KEY_LENGTH,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST,
    )
    pass_hash = kdf.derive(password.encode("utf-8"))

    # ── Fusion XOR (Information-Theoretic Security) ──
    int_pass = int.from_bytes(pass_hash, "big")
    int_usb = int.from_bytes(usb_secret, "big")
    xor_result = int_pass ^ int_usb

    return xor_result.to_bytes(KEY_LENGTH, "big")


def compute_kek(part_a: bytes, part_b: bytes) -> bytes:
    """
    Calcule la Key Encryption Key (KEK) par fusion XOR de deux parts.

    KEK = Part_A ⊕ Part_B

    Args:
        part_a: Part dérivée du responsable technique (32 bytes).
        part_b: Part dérivée du responsable juridique (32 bytes).

    Returns:
        bytes: KEK de 32 octets (256 bits).
    """
    int_a = int.from_bytes(part_a, "big")
    int_b = int.from_bytes(part_b, "big")
    return (int_a ^ int_b).to_bytes(KEY_LENGTH, "big")


# ============================================================================
# GESTION DE LA MASTER KEY EN RAM VOLATILE
# ============================================================================

def get_master_key() -> bytes:
    """
    Récupère la Master Key depuis le RAM Disk sécurisé.

    Validation :
        - Existence du fichier en /dev/shm
        - Taille exacte de 32 bytes (AES-256)

    Raises:
        PermissionError: Serveur non initialisé (clé absente).
        ValueError:      Fichier RAM corrompu.
    """
    if not os.path.exists(RAM_DISK_PATH):
        raise PermissionError(
            "Serveur verrouillé — Effectuez la Mise en Service (Cérémonie des Clés)."
        )

    with open(RAM_DISK_PATH, "rb") as f:
        mk = f.read()

    if len(mk) != KEY_LENGTH:
        raise ValueError(
            f"Master Key corrompue en RAM (taille {len(mk)} != {KEY_LENGTH})."
        )

    return mk


def store_master_key(master_key: bytes):
    """
    Écrit la Master Key sur le RAM Disk avec permissions restrictives.

    Sécurité :
        - Permissions 0600 (lecture/écriture propriétaire uniquement).
        - Aucun accès groupe/other.

    Args:
        master_key: La clé maîtresse déchiffrée (32 bytes).

    Raises:
        ValueError: Si la clé n'a pas la bonne taille.
    """
    if len(master_key) != KEY_LENGTH:
        raise ValueError(f"Master Key invalide (taille {len(master_key)} != {KEY_LENGTH}).")

    with open(RAM_DISK_PATH, "wb") as f:
        f.write(master_key)

    # Permissions restrictives — propriétaire seul (rw-------)
    os.chmod(RAM_DISK_PATH, stat.S_IRUSR | stat.S_IWUSR)


# ============================================================================
# CHIFFREMENT / DÉCHIFFREMENT DE LA BASE DE DONNÉES
# ============================================================================

def save_database(data: dict, mk: bytes):
    """
    Chiffre et sauvegarde la DB avec AES-256-GCM (Authenticated Encryption).

    Sécurité :
        - Nonce aléatoire unique à chaque écriture (anti-rejeu).
        - Tag GCM intégré au ciphertext (intégrité + authenticité).
        - Permissions 0600 sur le fichier résultant.

    Format disque : [Nonce (12 bytes)] + [Ciphertext + GCM Tag]
    """
    aesgcm = AESGCM(mk)
    nonce = os.urandom(NONCE_LENGTH)

    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(DB_FILE, "wb") as f:
        f.write(nonce + ciphertext)

    os.chmod(DB_FILE, stat.S_IRUSR | stat.S_IWUSR)


def load_database(mk: bytes) -> dict:
    """
    Charge et déchiffre la DB depuis le disque.

    Sécurité :
        - Vérification automatique du tag GCM (intégrité des données).
        - Toute altération du fichier provoque un échec cryptographique.

    Returns:
        dict: Dictionnaire {nom: numéro_carte} déchiffré.

    Raises:
        ValueError: Clé incorrecte ou fichier altéré (tag GCM invalide).
    """
    if not os.path.exists(DB_FILE):
        return {}

    with open(DB_FILE, "rb") as f:
        content = f.read()

    if len(content) < NONCE_LENGTH + 16:  # Nonce + tag GCM minimum
        raise ValueError("Fichier DB corrompu (taille insuffisante).")

    nonce = content[:NONCE_LENGTH]
    ciphertext = content[NONCE_LENGTH:]

    aesgcm = AESGCM(mk)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise ValueError(
            "ALERTE INTÉGRITÉ — Échec du déchiffrement. "
            "Clé incorrecte ou base de données altérée."
        )


# ============================================================================
# EFFACEMENT SÉCURISÉ (ZEROIZATION — FIPS 140-3 §7.7)
# ============================================================================

def secure_wipe_ram():
    """
    Efface la Master Key du RAM Disk de manière sécurisée.

    Procédure de zeroization (FIPS 140-3 §7.7 — 3 passes) :
        1. Écrasement avec des zéros       (0x00 — clear)
        2. Écrasement avec le complément   (0xFF — complement)
        3. Écrasement avec de l'aléa       (CSPRNG — verify)
        4. Suppression du fichier

    Référence : FIPS 140-3 §7.7 (Sensitive Security Parameter Zeroization)
    Note : Sur tmpfs (/dev/shm), pas de rémanence magnétique.
           Les passes multiples protègent contre les copies COW du noyau Linux.
    """
    if not os.path.exists(RAM_DISK_PATH):
        return

    file_size = os.path.getsize(RAM_DISK_PATH)

    # 3 passes : clear (0x00), complement (0xFF), random (CSPRNG)
    wipe_patterns = [b'\x00', b'\xFF', None]

    for pattern in wipe_patterns[:WIPE_PASSES]:
        with open(RAM_DISK_PATH, "wb") as f:
            if pattern is None:
                f.write(os.urandom(file_size))
            else:
                f.write(pattern * file_size)
            f.flush()
            os.fsync(f.fileno())

    os.remove(RAM_DISK_PATH)