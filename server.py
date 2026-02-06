import os
import sys
import json
import getpass
import crypto_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def service_1_i_mise_en_service():
    """Authentifie les responsables et déchiffre la MK en RAM"""
    print("\n--- SERVICE 1.i : MISE EN SERVICE (DÉMARRAGE) ---")
    
    if not os.path.exists("vault.json"):
        print("[ERREUR] Système non initialisé. Lancez setup.py d'abord.")
        return

    # 1. Chargement du Vault
    with open("vault.json", "r") as f:
        vault = json.load(f)
    salt = bytes.fromhex(vault["salt"])

    # 2. Authentification 2FA Simultanée
    try:
        # Responsable A
        print(">> Authentification Responsable TECHNIQUE")
        usb_path_a = input("Chemin Clé USB (ex: usb_tech/keyfile.bin) : ")
        pass_a = getpass.getpass("Mot de passe : ")
        part_a = crypto_utils.derive_part(pass_a, usb_path_a, salt)

        # Responsable B
        print(">> Authentification Responsable JURIDIQUE")
        usb_path_b = input("Chemin Clé USB (ex: usb_juridique/keyfile.bin) : ")
        pass_b = getpass.getpass("Mot de passe : ")
        part_b = crypto_utils.derive_part(pass_b, usb_path_b, salt)

        # 3. Reconstruction de la KEK
        int_a = int.from_bytes(part_a, "big")
        int_b = int.from_bytes(part_b, "big")
        kek = (int_a ^ int_b).to_bytes(32, "big")

        # 4. Déchiffrement de la Master Key
        aesgcm = AESGCM(kek)
        nonce = bytes.fromhex(vault["nonce"])
        ciphertext = bytes.fromhex(vault["ciphertext"])
        
        master_key = aesgcm.decrypt(nonce, ciphertext, None)
        
        # 5. Stockage en RAM Disk (Simulé dans /dev/shm)
        # On définit les droits en lecture seule pour l'utilisateur courant (0o600)
        with open(crypto_utils.RAM_DISK_PATH, "wb") as f:
            f.write(master_key)
        os.chmod(crypto_utils.RAM_DISK_PATH, 0o600) 

        print("\n[SUCCÈS] Authentification réussie.")
        print(f"[SECURE] Master Key chargée en RAM ({crypto_utils.RAM_DISK_PATH}).")
        print("Le serveur est prêt à traiter les paiements.")

    except Exception as e:
        print(f"\n[ÉCHEC] Authentification impossible : {e}")
        print("Alerte de sécurité : Tentative d'accès échouée.")

def service_1_ii_ajouter():
    print("\n--- SERVICE 1.ii : AJOUTER UNE PAIRE ---")
    try:
        mk = crypto_utils.get_master_key()
        db = crypto_utils.load_database(mk)
        
        nom = input("Nom du client : ")
        num = input("Numéro de Carte : ")
        
        db[nom] = num
        
        crypto_utils.save_database(db, mk)
        print(f"[OK] Carte ajoutée pour {nom}.")
        
    except Exception as e:
        print(f"[ERREUR] {e}")

def service_1_iii_supprimer():
    print("\n--- SERVICE 1.iii : SUPPRIMER UNE PAIRE ---")
    try:
        mk = crypto_utils.get_master_key()
        db = crypto_utils.load_database(mk)
        
        nom = input("Nom du client à supprimer : ")
        
        if nom in db:
            del db[nom]
            crypto_utils.save_database(db, mk)
            print(f"[OK] Données supprimées pour {nom}.")
        else:
            print("[INFO] Client introuvable.")
            
    except Exception as e:
        print(f"[ERREUR] {e}")

def service_1_iv_chercher():
    print("\n--- SERVICE 1.iv : CHERCHER UN N° DE CARTE ---")
    try:
        mk = crypto_utils.get_master_key()
        db = crypto_utils.load_database(mk)
        
        nom = input("Nom du client à chercher : ")
        
        if nom in db:
            print(f"--> Résultat : {db[nom]}")
        else:
            print("--> Résultat : Aucune donnée trouvée.")
            
    except Exception as e:
        print(f"[ERREUR] {e}")

def main_menu():
    while True:
        print("\n" + "="*40)
        print(" SERVEUR DE PAIEMENT SÉCURISÉ (PoC)")
        print("="*40)
        print("1. (1.i)   Mise en Service (Démarrage)")
        print("2. (1.ii)  Ajouter une carte")
        print("3. (1.iii) Supprimer une carte")
        print("4. (1.iv)  Rechercher une carte")
        print("5. Quitter (Efface la RAM)")
        
        choix = input("Votre choix : ")
        
        if choix == "1":
            service_1_i_mise_en_service()
        elif choix == "2":
            service_1_ii_ajouter()
        elif choix == "3":
            service_1_iii_supprimer()
        elif choix == "4":
            service_1_iv_chercher()
        elif choix == "5":
            # Nettoyage de sécurité avant de quitter
            if os.path.exists(crypto_utils.RAM_DISK_PATH):
                os.remove(crypto_utils.RAM_DISK_PATH)
                print("[SECURE] Master Key effacée de la RAM.")
            print("Arrêt du système.")
            sys.exit(0)

if __name__ == "__main__":
    main_menu()