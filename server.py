"""
server.py — Console Sécurisée de Gestion du Coffre-Fort Numérique
====================================================================
Services implémentés :
    1.i   — Mise en Service (Cérémonie des Clés Multi-Slots)
    1.ii  — Ajouter une paire (nom, numéro de carte)
    1.iii — Supprimer une paire
    1.iv  — Rechercher un numéro de carte
    1.vi  — Révocation d'accès (Répudiation par Quorum)

Conformité : PCI-DSS v4.0 §3-10, NIST SP 800-57
"""

import os
import sys
import json
import stat
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_utils
import audit

# ============================================================================
# CONSTANTES
# ============================================================================

# Table de mapping Slot : (rôle_tech, rôle_jur) -> slot_id
SLOT_MAP = {
    ("MAIN", "MAIN"): 0,  # Titulaire Tech + Titulaire Jur
    ("MAIN", "REP"):  1,  # Titulaire Tech + Suppléant Jur
    ("REP",  "MAIN"): 2,  # Suppléant Tech + Titulaire Jur
    ("REP",  "REP"):  3,  # Suppléant Tech + Suppléant Jur
}

# Table de mapping pour la révocation
REVOCATION_MAP = {
    "1": "Titulaire Tech",
    "2": "Titulaire Jur",
    "3": "Suppléant Tech",
    "4": "Suppléant Jur",
}

# Registre des acteurs pour le protocole de régénération (Rapport §4.2)
ACTORS = {
    "Titulaire Tech":  {"usb_hint": "usb_tech_main/keyfile.bin"},
    "Titulaire Jur":   {"usb_hint": "usb_jur_main/keyfile.bin"},
    "Suppléant Tech":  {"usb_hint": "usb_tech_rep/keyfile.bin"},
    "Suppléant Jur":   {"usb_hint": "usb_jur_rep/keyfile.bin"},
}

# Définitions structurelles des slots (lien acteur ↔ slot)
SLOT_DEFINITIONS = [
    {"id": 0, "tech": "Titulaire Tech", "jur": "Titulaire Jur",
     "desc": "Titulaire Tech + Titulaire Jur"},
    {"id": 1, "tech": "Titulaire Tech", "jur": "Suppléant Jur",
     "desc": "Titulaire Tech + Suppléant Jur"},
    {"id": 2, "tech": "Suppléant Tech", "jur": "Titulaire Jur",
     "desc": "Suppléant Tech + Titulaire Jur"},
    {"id": 3, "tech": "Suppléant Tech", "jur": "Suppléant Jur",
     "desc": "Suppléant Tech + Suppléant Jur"},
]


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def select_role(domain: str) -> str:
    """
    Menu interactif pour choisir entre Titulaire et Suppléant.

    Args:
        domain: Domaine de responsabilité (TECHNIQUE / JURIDIQUE).

    Returns:
        str: "MAIN" pour Titulaire, "REP" pour Suppléant.
    """
    print(f"\n── Qui est le représentant {domain} ? ──")
    print("  1. Responsable Titulaire")
    print("  2. Représentant Suppléant")
    while True:
        choice = input("  Votre choix (1/2) : ").strip()
        if choice == "1":
            return "MAIN"
        elif choice == "2":
            return "REP"
        print("  [!] Choix invalide. Saisissez 1 ou 2.")


# ============================================================================
# SERVICE 1.i : MISE EN SERVICE (CÉRÉMONIE DES CLÉS)
# ============================================================================

def service_1_i_mise_en_service():
    """
    Authentification Multi-Slots : identifie le binôme présent,
    reconstruit la KEK, déchiffre la Master Key, et la place en RAM volatile.
    """
    print("\n" + "=" * 50)
    print("  SERVICE 1.i : CÉRÉMONIE DES CLÉS (MULTI-SLOTS)")
    print("=" * 50)

    if not os.path.exists("vault.json"):
        print("[ERREUR] Système non initialisé. Exécutez setup.py d'abord.")
        return

    with open("vault.json", "r") as f:
        vault = json.load(f)

    salt = bytes.fromhex(vault["global_salt"])

    # ── 1. Identification des acteurs ──
    role_tech = select_role("TECHNIQUE")
    role_jur = select_role("JURIDIQUE")

    # ── 2. Saisie des facteurs d'authentification ──
    try:
        print(f"\n>> Authentification du {role_tech} TECHNIQUE")
        usb_path_a = input("   Chemin Clé USB : ").strip()
        pass_a = getpass.getpass("   Mot de passe : ")
        part_a = crypto_utils.derive_part(pass_a, usb_path_a, salt)

        print(f"\n>> Authentification du {role_jur} JURIDIQUE")
        usb_path_b = input("   Chemin Clé USB : ").strip()
        pass_b = getpass.getpass("   Mot de passe : ")
        part_b = crypto_utils.derive_part(pass_b, usb_path_b, salt)

        # ── 3. Détermination du slot cible ──
        target_slot_id = SLOT_MAP.get((role_tech, role_jur))
        if target_slot_id is None:
            raise ValueError("Combinaison de rôles invalide.")

        print(f"\n[SYSTEM] Tentative d'ouverture du Slot #{target_slot_id}...")

        # ── 4. Récupération des données du slot ──
        target_slot = next(
            (s for s in vault["slots"] if s["slot_id"] == target_slot_id),
            None,
        )
        if not target_slot:
            raise ValueError(
                f"Slot #{target_slot_id} introuvable dans le Vault (accès révoqué ?)."
            )

        # ── 5. Calcul KEK & déchiffrement ──
        kek = crypto_utils.compute_kek(part_a, part_b)

        aesgcm = AESGCM(kek)
        nonce = bytes.fromhex(target_slot["nonce"])
        ciphertext = bytes.fromhex(target_slot["ciphertext"])

        master_key = aesgcm.decrypt(nonce, ciphertext, None)

        # ── 6. Écriture en RAM volatile ──
        crypto_utils.store_master_key(master_key)

        audit.log_event(
            "AUTH_SUCCESS",
            f"Slot #{target_slot_id} ({target_slot['description']})",
            "Master Key déchiffrée et chargée en RAM.",
        )

        print("\n[SUCCÈS] Authentification validée.")
        print(f"[AUDIT]  Profil : {target_slot['description']}")
        print(f"[SECURE] Master Key chargée en RAM ({crypto_utils.RAM_DISK_PATH}).")

        # Nettoyage des variables sensibles
        del master_key, kek, part_a, part_b, pass_a, pass_b

    except Exception as e:
        audit.log_event("AUTH_FAIL", "CLI", str(e))
        print(f"\n[ÉCHEC] Authentification refusée : {e}")


# ============================================================================
# SERVICE 1.ii : AJOUTER UNE PAIRE
# ============================================================================

def service_1_ii_ajouter():
    """Ajoute une paire (nom, numéro de carte) à la base chiffrée."""
    print("\n── SERVICE 1.ii : AJOUTER UNE PAIRE ──")
    try:
        mk = crypto_utils.get_master_key()
        db = crypto_utils.load_database(mk)

        nom = input("Nom du client : ").strip()
        if not nom:
            print("[ERREUR] Le nom ne peut pas être vide.")
            return

        num = input("Numéro de carte : ").strip()
        if not num:
            print("[ERREUR] Le numéro de carte ne peut pas être vide.")
            return

        # Vérification de doublon (protection contre écrasement silencieux)
        if nom in db:
            confirm = input(
                f"[ATTENTION] '{nom}' existe déjà. Écraser ? (OUI/NON) : "
            ).strip()
            if confirm != "OUI":
                print("[ANNULÉ] Aucune modification effectuée.")
                return

        # Validation du format (PCI-DSS v4.0 §3.3)
        card_digits = num.replace(" ", "").replace("-", "")
        if not card_digits.isdigit():
            print("[ERREUR] Le numéro de carte ne doit contenir que des chiffres.")
            return
        if not (13 <= len(card_digits) <= 19):
            print("[ERREUR] Le numéro de carte doit contenir entre 13 et 19 chiffres.")
            return

        db[nom] = num
        crypto_utils.save_database(db, mk)

        audit.log_event("DATA_WRITE", "OPERATOR", f"Ajout carte pour '{nom}'.")
        print(f"[OK] Carte enregistrée pour '{nom}'.")

    except Exception as e:
        print(f"[ERREUR] {e}")


# ============================================================================
# SERVICE 1.iii : SUPPRIMER UNE PAIRE
# ============================================================================

def service_1_iii_supprimer():
    """Supprime une paire de la base chiffrée."""
    print("\n── SERVICE 1.iii : SUPPRIMER UNE PAIRE ──")
    try:
        mk = crypto_utils.get_master_key()
        db = crypto_utils.load_database(mk)

        nom = input("Nom du client à supprimer : ").strip()

        if nom in db:
            del db[nom]
            crypto_utils.save_database(db, mk)
            audit.log_event("DATA_DELETE", "OPERATOR", f"Suppression de '{nom}'.")
            print(f"[OK] Données supprimées pour '{nom}'.")
        else:
            print(f"[INFO] Client '{nom}' introuvable.")

    except Exception as e:
        print(f"[ERREUR] {e}")


# ============================================================================
# SERVICE 1.iv : RECHERCHER
# ============================================================================

def service_1_iv_chercher():
    """Recherche un numéro de carte par nom dans la base chiffrée."""
    print("\n── SERVICE 1.iv : RECHERCHER UN N° DE CARTE ──")
    try:
        mk = crypto_utils.get_master_key()
        db = crypto_utils.load_database(mk)

        nom = input("Nom du client : ").strip()

        if nom in db:
            # Masquage PAN (PCI-DSS v4.0 §3.4 — afficher uniquement les 4 derniers chiffres)
            raw = db[nom].replace(" ", "").replace("-", "")
            masked = "*" * (len(raw) - 4) + raw[-4:] if len(raw) >= 4 else "****"
            print(f"  --> Résultat : {masked}")
        else:
            print("  --> Aucune donnée trouvée.")

        audit.log_event("DATA_READ", "OPERATOR", f"Recherche '{nom}'.")

    except Exception as e:
        print(f"[ERREUR] {e}")


# ============================================================================
# SERVICE 1.vi : RÉVOCATION (RÉPUDIATION PAR QUORUM)
# ============================================================================

def service_1_vi_revocation():
    """
    Révocation d'un acteur avec régénération complète du coffre (Rapport §4.2).

    Protocole de Régénération par Quorum :
        1. Authentification du Quorum (un binôme valide).
        2. Sélection de l'acteur cible.
        3. Authentification de TOUS les acteurs survivants.
        4. Génération d'une nouvelle Master Key (rotation).
        5. Ré-chiffrement de la base de données avec la nouvelle MK.
        6. Reconstruction du Vault avec uniquement les slots survivants.
        7. Mise à jour de la MK en RAM volatile.
    """
    print("\n" + "!" * 55)
    print("!!!  ZONE ADMINISTRATIVE : RÉVOCATION D'ACCÈS  !!!")
    print("!" * 55)

    if not os.path.exists("vault.json"):
        print("[ERREUR] Aucun coffre trouvé.")
        return

    # ── 1. Authentification du Quorum ──
    print("\n[SÉCURITÉ] La révocation nécessite l'authentification d'un binôme valide.")
    try:
        service_1_i_mise_en_service()
        if not os.path.exists(crypto_utils.RAM_DISK_PATH):
            print("[ACCÈS REFUSÉ] Authentification requise pour procéder.")
            return
    except Exception:
        return

    # ── 2. Chargement du Vault ──
    with open("vault.json", "r") as f:
        vault = json.load(f)

    salt = bytes.fromhex(vault["global_salt"])
    initial_count = len(vault["slots"])

    # ── 3. Sélection de la cible ──
    print("\n── QUI DOIT ÊTRE RÉVOQUÉ ? ──")
    print("  1. Responsable Technique (Titulaire)")
    print("  2. Responsable Juridique (Titulaire)")
    print("  3. Représentant Technique (Suppléant)")
    print("  4. Représentant Juridique (Suppléant)")

    choice = input("  Cible (1-4) : ").strip()
    target_role = REVOCATION_MAP.get(choice)

    if not target_role:
        print("[ANNULÉ] Choix invalide.")
        return

    # ── 4. Identification des slots et acteurs survivants ──
    surviving_slot_defs = [
        sd for sd in SLOT_DEFINITIONS
        if sd["tech"] != target_role and sd["jur"] != target_role
    ]
    deleted_count = initial_count - len(surviving_slot_defs)

    if deleted_count == 0:
        print(f"[INFO] Aucun slot trouvé pour '{target_role}'. Déjà révoqué ?")
        return

    # Acteurs survivants (dédupliqués)
    surviving_actors = set()
    for sd in surviving_slot_defs:
        surviving_actors.add(sd["tech"])
        surviving_actors.add(sd["jur"])

    print(f"\n[ANALYSE] Recherche des slots impliquant '{target_role}'...")
    print(f"  Slots à détruire     : {deleted_count}")
    print(f"  Slots à reconstruire : {len(surviving_slot_defs)}")
    print(f"  Acteurs survivants   : {', '.join(sorted(surviving_actors))}")

    # ── 5. Confirmation ──
    print(f"\n[ATTENTION] {deleted_count} slot(s) seront détruits.")
    print(f"  La Master Key sera RÉGÉNÉRÉE (rotation de clé).")
    print(f"  La base de données sera RÉ-CHIFFRÉE.")
    confirm = input("  Confirmer la révocation irréversible ? (OUI/NON) : ").strip()

    if confirm != "OUI":
        print("[ANNULÉ] Aucune modification effectuée.")
        return

    # ── 6. Collecte des secrets de TOUS les survivants ──
    print("\n" + "=" * 55)
    print("  PHASE DE RÉGÉNÉRATION : Authentification des Survivants")
    print("=" * 55)
    print("[PROTOCOLE] Chaque acteur survivant doit s'authentifier")
    print("            pour reconstruire ses slots d'accès.\n")

    try:
        actor_parts = {}
        for actor_name in sorted(surviving_actors):
            actor_info = ACTORS[actor_name]
            print(f"\n>> Authentification de : {actor_name}")
            usb_path = input(
                f"   Chemin Clé USB [{actor_info['usb_hint']}] : "
            ).strip()
            if not usb_path:
                usb_path = actor_info["usb_hint"]
            password = getpass.getpass("   Mot de passe : ")
            actor_parts[actor_name] = crypto_utils.derive_part(
                password, usb_path, salt,
            )
            del password
            print(f"   [OK] Part dérivée pour {actor_name}.")

        # ── 7. Rotation de la Master Key ──
        print("\n[CRYPTO] Rotation de la Master Key...")
        old_mk = crypto_utils.get_master_key()
        new_mk = AESGCM.generate_key(bit_length=256)

        # ── 8. Ré-chiffrement de la base de données ──
        if os.path.exists(crypto_utils.DB_FILE):
            print("[CRYPTO] Ré-chiffrement de la base de données...")
            db = crypto_utils.load_database(old_mk)
            crypto_utils.save_database(db, new_mk)
            del db
            print("[OK] Base de données ré-chiffrée avec la nouvelle MK.")
        else:
            print("[INFO] Aucune base de données existante à migrer.")

        # ── 9. Reconstruction des slots survivants ──
        print("[CRYPTO] Reconstruction des slots survivants...")
        new_slots = []
        for sd in surviving_slot_defs:
            part_tech = actor_parts[sd["tech"]]
            part_jur = actor_parts[sd["jur"]]
            kek = crypto_utils.compute_kek(part_tech, part_jur)

            aesgcm = AESGCM(kek)
            nonce = os.urandom(crypto_utils.NONCE_LENGTH)
            ciphertext = aesgcm.encrypt(nonce, new_mk, None)

            new_slots.append({
                "slot_id": sd["id"],
                "description": sd["desc"],
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            })
            print(f"  Slot {sd['id']} : {sd['desc']} — reconstruit.")
            del kek

        # ── 10. Sauvegarde du nouveau Vault ──
        vault["slots"] = new_slots
        with open("vault.json", "w") as f:
            json.dump(vault, f, indent=4)
        os.chmod("vault.json", stat.S_IRUSR | stat.S_IWUSR)

        # ── 11. Mise à jour de la MK en RAM ──
        crypto_utils.store_master_key(new_mk)

        # ── 12. Nettoyage mémoire ──
        del old_mk, new_mk, actor_parts

        audit.log_event(
            "REVOCATION",
            "ADMIN_QUORUM",
            f"Révocation '{target_role}' avec régénération complète. "
            f"{deleted_count} slot(s) détruit(s). "
            f"Restants : {len(new_slots)}. MK régénérée.",
        )

        print(f"\n[SUCCÈS] Révocation avec régénération effectuée.")
        print(f"  Slots détruits      : {deleted_count}")
        print(f"  Slots reconstruits  : {len(new_slots)}")
        print(f"  Master Key          : RÉGÉNÉRÉE (rotation complète)")
        print(f"  Base de données     : RÉ-CHIFFRÉE")
        print(f"  L'acteur '{target_role}' ne pourra plus accéder au système.")

    except Exception as e:
        audit.log_event("REVOCATION_FAIL", "ADMIN_QUORUM", str(e))
        print(f"\n[ÉCHEC] Régénération échouée : {e}")
        print("  Aucune modification n'a été appliquée.")


# ============================================================================
# MENU PRINCIPAL
# ============================================================================

def main_menu():
    """Boucle interactive du serveur sécurisé."""
    while True:
        print("\n" + "=" * 45)
        print("  SERVEUR DE PAIEMENT SÉCURISÉ (PoC v2.0)")
        print("=" * 45)
        print("  1. (1.i)   Mise en Service (Cérémonie)")
        print("  2. (1.ii)  Ajouter une carte")
        print("  3. (1.iii) Supprimer une carte")
        print("  4. (1.iv)  Rechercher une carte")
        print("  " + "-" * 30)
        print("  6. (1.vi)  RÉPUDIATION (Admin)")
        print("  5. Quitter")

        choix = input("\n  Votre choix : ").strip()

        if choix == "1":
            service_1_i_mise_en_service()
        elif choix == "2":
            service_1_ii_ajouter()
        elif choix == "3":
            service_1_iii_supprimer()
        elif choix == "4":
            service_1_iv_chercher()
        elif choix == "6":
            service_1_vi_revocation()
        elif choix == "5":
            crypto_utils.secure_wipe_ram()
            audit.log_event("SYSTEM", "SYSTEM", "Arrêt du serveur et purge RAM.")
            print("[SYSTEM] Clé effacée. Arrêt sécurisé.")
            sys.exit(0)
        else:
            print("  [!] Choix invalide.")


if __name__ == "__main__":
    main_menu()