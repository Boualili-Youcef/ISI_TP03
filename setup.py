"""
setup.py — Service 1.v : Initialisation du Coffre Multi-Slots
===============================================================
Responsabilités :
    - Enrôlement des 4 acteurs (2 Titulaires + 2 Suppléants)
    - Génération de la Master Key (AES-256)
    - Création des 4 Slots de déchiffrement (Key Wrapping)
    - Sauvegarde du Vault V2 sur disque

Conformité : PCI-DSS v4.0 §3, NIST SP 800-57 (Key Management)
"""

import os
import json
import stat
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_utils
import audit

# ============================================================================
# CONSTANTES
# ============================================================================

MIN_PASSWORD_LENGTH = 12

# Liste noire de mots de passe communs (NIST SP 800-63B §5.1.1.2)
# En production : utiliser une base complète (ex: HaveIBeenPwned — 847M entrées)
BLACKLISTED_PASSWORDS = [
    "password1234", "admin1234567", "qwerty123456",
    "123456789012", "changeme1234", "welcome12345",
    "letmein12345", "master123456", "trustno1pass",
    "iloveyou1234", "dragon123456", "monkey1234567",
]

# Matrice des combinaisons valides (Slots)
SLOT_COMBINATIONS = [
    {"id": 0, "desc": "Titulaire Tech + Titulaire Jur"},
    {"id": 1, "desc": "Titulaire Tech + Suppléant Jur"},
    {"id": 2, "desc": "Suppléant Tech + Titulaire Jur"},
    {"id": 3, "desc": "Suppléant Tech + Suppléant Jur"},
]


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def _validate_password(password: str, role_name: str):
    """
    Vérifie la robustesse d'un mot de passe selon les standards actuels.

    Conformité :
        - PCI-DSS v4.0 §8.3.6 : longueur >= 12, complexité alphanumerique + spéciale
        - NIST SP 800-63B §5.1.1.2 : vérification contre les mots de passe compromis

    Critères appliqués :
        - Longueur >= MIN_PASSWORD_LENGTH (12 caractères)
        - Au moins 1 majuscule (A-Z)
        - Au moins 1 minuscule (a-z)
        - Au moins 1 chiffre (0-9)
        - Au moins 1 caractère spécial (!@#$%^&*...)
        - Non présent dans la liste noire (mots de passe courants)

    Raises:
        ValueError: Si un critère de robustesse n'est pas satisfait.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Mot de passe trop court pour [{role_name}] "
            f"(minimum {MIN_PASSWORD_LENGTH} caractères)."
        )
    if not any(c.isupper() for c in password):
        raise ValueError(f"Le mot de passe de [{role_name}] doit contenir au moins 1 majuscule.")
    if not any(c.islower() for c in password):
        raise ValueError(f"Le mot de passe de [{role_name}] doit contenir au moins 1 minuscule.")
    if not any(c.isdigit() for c in password):
        raise ValueError(f"Le mot de passe de [{role_name}] doit contenir au moins 1 chiffre.")
    if not any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\" for c in password):
        raise ValueError(
            f"Le mot de passe de [{role_name}] doit contenir au moins 1 caractère spécial "
            f"(!@#$%^&*...)."
        )
    if password.lower() in BLACKLISTED_PASSWORDS:
        raise ValueError(
            f"Le mot de passe de [{role_name}] est trop courant "
            f"(NIST SP 800-63B — liste noire de mots de passe compromis)."
        )


def setup_actor(role_name: str, folder_name: str) -> tuple:
    """
    Enrôle un acteur : génère son facteur physique et acquiert son mot de passe.

    Args:
        role_name:   Nom lisible du rôle (pour affichage).
        folder_name: Répertoire simulant le support USB.

    Returns:
        tuple: (password: str, usb_path: str)
    """
    os.makedirs(folder_name, exist_ok=True)
    usb_path = os.path.join(folder_name, "keyfile.bin")

    # Génération du secret physique (256 bits CSPRNG)
    usb_secret = os.urandom(crypto_utils.USB_KEY_LENGTH)
    with open(usb_path, "wb") as f:
        f.write(usb_secret)
    os.chmod(usb_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    print(f"[OK] Clé USB générée pour {role_name} -> {usb_path}")

    # Acquisition et validation du mot de passe
    while True:
        password = getpass.getpass(f"Définir mot de passe pour [{role_name}] : ")
        try:
            _validate_password(password, role_name)
        except ValueError as e:
            print(f"[ERREUR] {e}")
            continue

        confirm = getpass.getpass(f"Confirmer mot de passe pour [{role_name}] : ")
        if password != confirm:
            print("[ERREUR] Les mots de passe ne correspondent pas. Réessayez.")
            continue
        break

    return password, usb_path


# ============================================================================
# SERVICE 1.v : INITIALISATION
# ============================================================================

def initialisation_service_1_v():
    """
    Procédure complète d'initialisation du coffre multi-slots.

    Étapes :
        1. Enrôlement des 4 acteurs (facteurs physiques + mots de passe)
        2. Génération de la Master Key AES-256
        3. Dérivation des 4 parts individuelles
        4. Création des 4 Slots (Key Wrapping : MK chiffrée par KEK)
        5. Sauvegarde du Vault V2 sur disque
    """
    print("=" * 60)
    print("  SERVICE 1.v : INITIALISATION MULTI-SLOTS (DÉLÉGATION)")
    print("=" * 60)
    print("Configuration : 4 acteurs (2 Responsables + 2 Représentants)\n")

    # ── 1. Enrôlement des acteurs ──
    print("── Phase 1 : Enrôlement des Responsables Titulaires ──")
    pass_rt, usb_rt = setup_actor("Resp. Technique (Titulaire)", "usb_tech_main")
    pass_rj, usb_rj = setup_actor("Resp. Juridique (Titulaire)", "usb_jur_main")

    print("\n" + "-" * 40)
    print("── Phase 2 : Enrôlement des Représentants Suppléants ──")
    pass_rep_t, usb_rep_t = setup_actor("Représentant Tech (Suppléant)", "usb_tech_rep")
    pass_rep_j, usb_rep_j = setup_actor("Représentant Jur (Suppléant)", "usb_jur_rep")

    # ── 2. Génération de la Master Key ──
    master_key = AESGCM.generate_key(bit_length=256)
    global_salt = os.urandom(crypto_utils.SALT_LENGTH)

    # ── 3. Dérivation des parts individuelles ──
    print("\n[CRYPTO] Dérivation des parts (Argon2id + XOR)...")
    part_rt = crypto_utils.derive_part(pass_rt, usb_rt, global_salt)
    part_rj = crypto_utils.derive_part(pass_rj, usb_rj, global_salt)
    part_rep_t = crypto_utils.derive_part(pass_rep_t, usb_rep_t, global_salt)
    part_rep_j = crypto_utils.derive_part(pass_rep_j, usb_rep_j, global_salt)

    # Matrice des combinaisons : (part_tech, part_jur)
    part_matrix = [
        (part_rt, part_rj),       # Slot 0 : Titulaire + Titulaire
        (part_rt, part_rep_j),    # Slot 1 : Titulaire Tech + Suppléant Jur
        (part_rep_t, part_rj),    # Slot 2 : Suppléant Tech + Titulaire Jur
        (part_rep_t, part_rep_j), # Slot 3 : Suppléant + Suppléant
    ]

    # ── 4. Création des Slots (Key Wrapping) ──
    print("[CRYPTO] Chiffrement de la Master Key pour les 4 Slots...")
    slots_data = []

    for combo, (part_a, part_b) in zip(SLOT_COMBINATIONS, part_matrix):
        kek_slot = crypto_utils.compute_kek(part_a, part_b)

        aesgcm = AESGCM(kek_slot)
        nonce = os.urandom(crypto_utils.NONCE_LENGTH)
        ciphertext = aesgcm.encrypt(nonce, master_key, None)

        slots_data.append({
            "slot_id": combo["id"],
            "description": combo["desc"],
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        })
        print(f"  Slot {combo['id']} : {combo['desc']}")

    # ── 5. Sauvegarde du Vault V2 ──
    vault = {
        "version": 2,
        "algo": "AES-256-GCM",
        "kdf": "Argon2id",
        "global_salt": global_salt.hex(),
        "slots": slots_data,
    }

    with open("vault.json", "w") as f:
        json.dump(vault, f, indent=4)
    os.chmod("vault.json", stat.S_IRUSR | stat.S_IWUSR)  # 0600

    # ── Nettoyage mémoire ──
    del master_key, part_rt, part_rj, part_rep_t, part_rep_j
    del pass_rt, pass_rj, pass_rep_t, pass_rep_j

    audit.log_event("SYSTEM", "SETUP", "Initialisation Multi-Slots terminée (4 slots créés).")

    print("\n" + "=" * 60)
    print("  INITIALISATION TERMINÉE")
    print("=" * 60)
    print("Master Key sécurisée dans 4 slots indépendants.")
    print("IMPORTANT : Conservez les clés USB en lieu sûr (coffre physique).")


if __name__ == "__main__":
    initialisation_service_1_v()