import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import crypto_utils
import getpass

def initialisation_service_1_v():
    print("=== SERVICE 1.v : INITIALISATION SÉCURISÉE ===")
    
    # 1. Création des clés USB (Simulation)
    os.makedirs("usb_tech", exist_ok=True)
    os.makedirs("usb_juridique", exist_ok=True)
    
    usb_secret_a = os.urandom(32)
    usb_secret_b = os.urandom(32)
    
    with open("usb_tech/keyfile.bin", "wb") as f:
        f.write(usb_secret_a)
    print("[OK] Clé USB Responsable Technique générée (usb_tech/keyfile.bin)")
    
    with open("usb_juridique/keyfile.bin", "wb") as f:
        f.write(usb_secret_b)
    print("[OK] Clé USB Responsable Juridique générée (usb_juridique/keyfile.bin)")

    # 2. Saisie des mots de passe
    print("\n--- Enrôlement des Responsables ---")
    pass_a = getpass.getpass("Définir Mot de passe (Tech) : ")
    pass_b = getpass.getpass("Définir Mot de passe (Juridique) : ")

    # 3. Génération de la MASTER KEY (MK) - La clé qui ne changera jamais
    master_key = AESGCM.generate_key(bit_length=256) # 32 bytes
    
    # 4. Calcul de la KEK (Key Encryption Key) via XOR
    salt = os.urandom(16) # Sel unique pour l'application
    
    part_a = crypto_utils.derive_part(pass_a, "usb_tech/keyfile.bin", salt)
    part_b = crypto_utils.derive_part(pass_b, "usb_juridique/keyfile.bin", salt)
    
    # KEK = Part_A XOR Part_B
    int_a = int.from_bytes(part_a, "big")
    int_b = int.from_bytes(part_b, "big")
    kek = (int_a ^ int_b).to_bytes(32, "big")

    # 5. Chiffrement de la Master Key (Key Wrapping)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    encrypted_mk = aesgcm.encrypt(nonce, master_key, None)

    # 6. Sauvegarde du Vault (Coffre)
    vault_data = {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": encrypted_mk.hex()
    }
    
    with open("vault.json", "w") as f:
        json.dump(vault_data, f, indent=4)
        
    print("\n[SUCCÈS] Système initialisé.")
    print(" - Master Key générée et chiffrée dans 'vault.json'")
    print(" - Base de données prête (vide).")
    print("ATTENTION : La Master Key a été effacée de la mémoire de ce script.")

if __name__ == "__main__":
    initialisation_service_1_v()