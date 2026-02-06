import os
import json
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import crypto_utils

def setup_actor(role_name, folder_name):
    """Génère le facteur physique pour un acteur donné."""
    os.makedirs(folder_name, exist_ok=True)
    usb_path = f"{folder_name}/keyfile.bin"
    
    # Génération du secret physique (Avoir)
    usb_secret = os.urandom(32)
    with open(usb_path, "wb") as f:
        f.write(usb_secret)
    
    print(f"[OK] Clé USB générée pour {role_name} -> {usb_path}")
    
    # Acquisition du secret mémorable (Savoir)
    password = getpass.getpass(f"Définir Mot de passe pour [{role_name}] : ")
    return password, usb_path

def initialisation_service_1_v():
    print("=== SERVICE 1.v : INITIALISATION MULTI-SLOTS (DELEGATION) ===")
    print("Configuration de l'architecture à 4 acteurs (2 Responsables + 2 Représentants)\n")

    # 1. Enrôlement des 4 acteurs (Identifiants Uniques)
    # Responsables Titulaires
    pass_rt, usb_rt = setup_actor("Resp. Technique (Titulaire)", "usb_tech_main")
    pass_rj, usb_rj = setup_actor("Resp. Juridique (Titulaire)", "usb_jur_main")
    
    print("-" * 40)
    
    # Représentants (Suppléants)
    pass_rep_t, usb_rep_t = setup_actor("Représentant Tech (Suppléant)", "usb_tech_rep")
    pass_rep_j, usb_rep_j = setup_actor("Représentant Jur (Suppléant)", "usb_jur_rep")

    # 2. Génération de la MASTER KEY Unique (Celle qui chiffre les données)
    master_key = AESGCM.generate_key(bit_length=256)
    global_salt = os.urandom(16)

    # 3. Préparation des combinaisons (Parts de secrets)
    # On dérive les parts individuelles
    part_rt = crypto_utils.derive_part(pass_rt, usb_rt, global_salt)
    part_rj = crypto_utils.derive_part(pass_rj, usb_rj, global_salt)
    part_rep_t = crypto_utils.derive_part(pass_rep_t, usb_rep_t, global_salt)
    part_rep_j = crypto_utils.derive_part(pass_rep_j, usb_rep_j, global_salt)

    # Dictionnaire des combinaisons valides (Les 4 Slots)
    combinations = [
        {"id": 0, "desc": "Titulaire Tech + Titulaire Jur", "parts": (part_rt, part_rj)},
        {"id": 1, "desc": "Titulaire Tech + Suppléant Jur", "parts": (part_rt, part_rep_j)},
        {"id": 2, "desc": "Suppléant Tech + Titulaire Jur", "parts": (part_rep_t, part_rj)},
        {"id": 3, "desc": "Suppléant Tech + Suppléant Jur", "parts": (part_rep_t, part_rep_j)},
    ]

    slots_data = []

    # 4. Création des Slots (Key Wrapping)
    print("\n[CRYPTO] Chiffrement de la Master Key pour les 4 Slots...")
    
    for combo in combinations:
        # Fusion des parts (XOR) pour créer la KEK du slot
        part_a, part_b = combo["parts"]
        int_a = int.from_bytes(part_a, "big")
        int_b = int.from_bytes(part_b, "big")
        kek_slot = (int_a ^ int_b).to_bytes(32, "big")

        # Chiffrement de la MK avec cette KEK
        aesgcm = AESGCM(kek_slot)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, master_key, None)

        # Ajout au manifest
        slots_data.append({
            "slot_id": combo["id"],
            "description": combo["desc"], # Métadonnée pour l'audit
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        })
        print(f" - Slot {combo['id']} créé ({combo['desc']})")

    # 5. Sauvegarde du Vault V2
    vault = {
        "version": 2,
        "global_salt": global_salt.hex(),
        "slots": slots_data
    }

    with open("vault.json", "w") as f:
        json.dump(vault, f, indent=4)

    print("\n[SUCCÈS] Système initialisé avec gestion des délégations.")
    print("Master Key sécurisée dans 4 slots indépendants.")
    del master_key # Nettoyage mémoire

if __name__ == "__main__":
    initialisation_service_1_v()