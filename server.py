import os
import sys
import json
import getpass
import crypto_utils
import audit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import audit

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

        # [AJOUT AUDIT]
        audit.log_event(
            event_type="AUTH_SUCCESS",
            user_context=f"Slot #{target_slot_id} ({target_slot['description']})",
            description="Master Key déchiffrée et chargée en RAM."
        )

        # 6. Écriture en RAM
        with open(crypto_utils.RAM_DISK_PATH, "wb") as f:
            f.write(master_key)
        os.chmod(crypto_utils.RAM_DISK_PATH, 0o600)

        print("\n[SUCCÈS] Authentification Validée.")
        print(f"[AUDIT] Accès autorisé via le profil : {target_slot['description']}")
        print(f"[SECURE] Master Key chargée en RAM via le Slot {target_slot_id}.")
        audit.log_event(
            event_type="AUTH_SUCCESS",
            user_context=f"Slot #{target_slot_id} ({target_slot['description']})",
            description="Master Key déchiffrée et chargée en RAM."
        )

        print("\n[SUCCÈS] Authentification Validée.")

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

        # [AJOUT AUDIT] - On ne log pas le nom du client (Confidentialité !), juste l'ID ou le fait qu'on a ajouté.
        audit.log_event("DATA_WRITE", "OPERATOR", f"Ajout d'une nouvelle carte (Hash: {hash(num)})")
        
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
        
def service_1_vi_revocation():
    """
    SERVICE 1.vi : RÉPUDIATION (REVOCATION DE DROITS)
    Principe : Analyse le Vault et détruit les slots cryptographiques associés à un acteur.
    Nécessite une authentification forte (Quorum) pour autoriser l'écriture sur le disque.
    """
    print("\n" + "!"*50)
    print("!!! ZONE ADMINISTRATIVE : RÉVOCATION D'ACCÈS !!!")
    print("!"*50)

    if not os.path.exists("vault.json"):
        print("[ERREUR] Aucun coffre trouvé.")
        return

    # 1. Authentification du Quorum (Preuve d'autorité)
    print("\n[SECURITE] Une révocation nécessite l'authentification d'un administrateur restant.")
    # On réutilise la fonction de mise en service pour prouver qu'on a le droit de toucher au vault
    # Dans un système réel, on demanderait la signature de TOUS les survivants.
    # Pour le PoC, on demande au moins un binôme valide (ex: les deux titulaires).
    try:
        service_1_i_mise_en_service() 
        # Si ça échoue, le script s'arrête ou lève une exception, donc on ne va pas plus loin.
        if not os.path.exists(crypto_utils.RAM_DISK_PATH):
            print("[ACCES REFUSÉ] Impossible de procéder à la révocation sans authentification valide.")
            return
    except Exception:
        return

    # 2. Chargement du Vault
    with open("vault.json", "r") as f:
        vault = json.load(f)
    
    slots = vault["slots"]
    initial_count = len(slots)

    # 3. Sélection de la cible
    print("\n--- QUI DOIT ÊTRE RÉVOQUÉ ? ---")
    print("1. Responsable Technique (Titulaire)")
    print("2. Responsable Juridique (Titulaire)")
    print("3. Représentant Technique (Suppléant)")
    print("4. Représentant Juridique (Suppléant)")
    
    choice = input("Sélectionnez la cible (1-4) : ")
    target_role = ""
    
    if choice == "1": target_role = "Titulaire Tech"
    elif choice == "2": target_role = "Titulaire Jur"
    elif choice == "3": target_role = "Suppléant Tech"
    elif choice == "4": target_role = "Suppléant Jur"
    else: return

    print(f"\n[ANALYSE] Recherche des slots impliquant : '{target_role}'...")

    # 4. Filtrage des Slots (La Révocation)
    # On garde uniquement les slots qui NE contiennent PAS la chaîne de caractère du rôle cible
    surviving_slots = [
        s for s in slots 
        if target_role not in s["description"]
    ]

    deleted_count = initial_count - len(surviving_slots)

    if deleted_count == 0:
        print("[INFO] Aucun slot trouvé pour cet acteur. Il a peut-être déjà été révoqué.")
        return

    # 5. Application de la Sentence (Écriture Disque)
    print(f"[ATTENTION] Vous allez détruire {deleted_count} slots d'accès.")
    confirm = input("Confirmer la révocation irréversible ? (OUI/NON) : ")
    
    if confirm == "OUI":
        vault["slots"] = surviving_slots
        
        # On sauvegarde le nouveau Vault épuré
        with open("vault.json", "w") as f:
            json.dump(vault, f, indent=4)
            
        print(f"\n[SUCCÈS] Révocation effectuée.")
        print(f" - Slots restants : {len(surviving_slots)}")
        print(f" - L'acteur '{target_role}' ne pourra plus jamais participer au déchiffrement.")

        # [AJOUT AUDIT]
        audit.log_event(
            event_type="REVOCATION",
            user_context="ADMIN_QUORUM", # Car validé par les titulaires
            description=f"Destruction des droits pour le rôle : {target_role}. Slots restants : {len(surviving_slots)}"
        )
    else:
        print("[ANNULATION] Aucune modification effectuée.")

def main_menu():
    while True:
        print("\n" + "="*40)
        print(" SERVEUR DE PAIEMENT SÉCURISÉ (PoC)")
        print("="*40)
        print("1. (1.i)   Mise en Service (Cérémonie)")
        print("2. (1.ii)  Ajouter une carte")
        print("3. (1.iii) Supprimer une carte")
        print("4. (1.iv)  Rechercher une carte")
        print("-" * 20)
        print("6. (1.vi)  RÉPUDIATION (Admin)")
        print("5. Quitter")
        
        choix = input("Votre choix : ")
        
        if choix == "1": service_1_i_mise_en_service()
        elif choix == "2": service_1_ii_ajouter()
        elif choix == "3": service_1_iii_supprimer()
        elif choix == "4": service_1_iv_chercher()
        elif choix == "6": service_1_vi_revocation()
        elif choix == "5":
            crypto_utils.secure_wipe_ram()
            audit.log_event("SYSTEM", "SYSTEM", "Arrêt du serveur et purge RAM.")
            sys.exit(0)

if __name__ == "__main__":
    main_menu()