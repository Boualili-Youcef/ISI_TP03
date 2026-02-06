import os
import sys
import json
import getpass
import crypto_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def select_role(domain):
    """Menu pour choisir entre Titulaire et Suppléant"""
    print(f"\n--- Qui est le représentant {domain} ? ---")
    print("1. Responsable Titulaire")
    print("2. Représentant Suppléant")
    while True:
        choice = input("Votre choix (1/2) : ")
        if choice == "1":
            return "MAIN"
        elif choice == "2":
            return "REP"

def service_1_i_mise_en_service():
    """Version Multi-Slots : Identifie les acteurs et ouvre le bon slot"""
    print("\n--- SERVICE 1.i : CÉRÉMONIE DES CLÉS (MULTI-SLOTS) ---")
    
    if not os.path.exists("vault.json"):
        print("[ERREUR] Système non initialisé.")
        return

    with open("vault.json", "r") as f:
        vault = json.load(f)
    
    salt = bytes.fromhex(vault["global_salt"])

    # 1. Identification des Acteurs (Discrimination)
    # Le système demande explicitement qui est là.
    role_tech = select_role("TECHNIQUE")
    role_jur = select_role("JURIDIQUE")

    # 2. Saisie des Facteurs
    try:
        print(f"\n>> Authentification {role_tech} (TECH)")
        usb_path_a = input("Chemin Clé USB : ")
        pass_a = getpass.getpass("Mot de passe : ")
        part_a = crypto_utils.derive_part(pass_a, usb_path_a, salt)

        print(f"\n>> Authentification {role_jur} (JURIDIQUE)")
        usb_path_b = input("Chemin Clé USB : ")
        pass_b = getpass.getpass("Mot de passe : ")
        part_b = crypto_utils.derive_part(pass_b, usb_path_b, salt)

        # 3. Détermination du Slot Cible
        # Logique de mapping : 
        # MAIN+MAIN=0, MAIN+REP=1, REP+MAIN=2, REP+REP=3
        target_slot_id = 0
        if role_tech == "MAIN" and role_jur == "MAIN": target_slot_id = 0
        if role_tech == "MAIN" and role_jur == "REP":  target_slot_id = 1
        if role_tech == "REP"  and role_jur == "MAIN": target_slot_id = 2
        if role_tech == "REP"  and role_jur == "REP":  target_slot_id = 3

        print(f"\n[SYSTEM] Tentative d'ouverture du Slot #{target_slot_id}...")

        # 4. Récupération des données du Slot
        target_slot = None
        for slot in vault["slots"]:
            if slot["slot_id"] == target_slot_id:
                target_slot = slot
                break
        
        if not target_slot:
            raise ValueError("Slot introuvable dans le Vault.")

        # 5. Calcul de la KEK et Déchiffrement
        int_a = int.from_bytes(part_a, "big")
        int_b = int.from_bytes(part_b, "big")
        kek = (int_a ^ int_b).to_bytes(32, "big")

        aesgcm = AESGCM(kek)
        nonce = bytes.fromhex(target_slot["nonce"])
        ciphertext = bytes.fromhex(target_slot["ciphertext"])
        
        master_key = aesgcm.decrypt(nonce, ciphertext, None)

        # 6. Écriture en RAM
        with open(crypto_utils.RAM_DISK_PATH, "wb") as f:
            f.write(master_key)
        os.chmod(crypto_utils.RAM_DISK_PATH, 0o600)

        print("\n[SUCCÈS] Authentification Validée.")
        print(f"[AUDIT] Accès autorisé via le profil : {target_slot['description']}")
        print(f"[SECURE] Master Key chargée en RAM via le Slot {target_slot_id}.")

    except Exception as e:
        print(f"\n[ÉCHEC CRITIQUE] Authentification refusée : {e}")
        print("Vérifiez que les bonnes personnes utilisent les bons slots.")

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