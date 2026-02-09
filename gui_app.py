"""
gui_app.py — Interface Graphique Sécurisée du Coffre-Fort Numérique
=====================================================================
Responsabilités :
    - Authentification Double Facteur via interface graphique
    - Opérations CRUD sur la base de données chiffrée
    - Procédure de révocation avec double confirmation
    - Nettoyage sécurisé des secrets en mémoire (widgets + variables)

Conformité : PCI-DSS v4.0 §3-10, NIST SP 800-57
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import os
import json

import crypto_utils
import audit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============================================================================
# CONSTANTES
# ============================================================================

# Mapping des slots : (role_tech, role_jur) -> slot_id
SLOT_MAP = {
    ("MAIN", "MAIN"): 0,
    ("MAIN", "REP"):  1,
    ("REP",  "MAIN"): 2,
    ("REP",  "REP"):  3,
}

# Mapping de révocation : choix -> sous-chaîne dans description du slot
REVOCATION_MAP = {
    1: "Titulaire Tech",
    2: "Titulaire Jur",
    3: "Suppléant Tech",
    4: "Suppléant Jur",
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

# Nombre max de tentatives avant verrouillage temporaire
MAX_AUTH_FAILURES = 5


class SecureBankingApp(tk.Tk):
    """Application de gestion du Coffre-Fort Numérique sécurisé."""

    def __init__(self):
        super().__init__()
        self.title("BlackRock Secure Vault - Management Console")
        self.geometry("900x650")
        self.configure(bg="#2d2d2d")

        # Variables d'état
        self.usb_path_tech = tk.StringVar()
        self.usb_path_jur = tk.StringVar()
        self.role_tech = tk.StringVar(value="MAIN")
        self.role_jur = tk.StringVar(value="MAIN")
        self.auth_failures = 0

        self._setup_styles()
        self._setup_ui()

    # ==================================================================
    # STYLES & THÈME
    # ==================================================================

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        self.colors = {
            "bg":      "#2d2d2d",
            "fg":      "#ffffff",
            "primary": "#2196f3",
            "danger":  "#f44336",
            "success": "#4caf50",
            "panel":   "#424242",
            "input":   "#616161",
        }

        c = self.colors
        style.configure("TFrame",          background=c["bg"])
        style.configure("TLabel",          background=c["bg"], foreground=c["fg"], font=("Helvetica", 10))
        style.configure("Header.TLabel",   font=("Helvetica", 18, "bold"), foreground=c["primary"])
        style.configure("SubHeader.TLabel", font=("Helvetica", 12, "bold"), foreground="#bdbdbd")

        style.configure("TButton",         font=("Helvetica", 10), borderwidth=0)
        style.map("TButton", background=[("active", "#64b5f6")])
        style.configure("Primary.TButton", background=c["primary"], foreground="white")
        style.configure("Danger.TButton",  background=c["danger"],  foreground="white")
        style.configure("Success.TButton", background=c["success"], foreground="white")

        style.configure("TEntry", fieldbackground=c["input"], foreground="white")

        style.configure("TNotebook",     background=c["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=c["panel"], foreground="white", padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", c["primary"])])

    # ==================================================================
    # LAYOUT
    # ==================================================================

    def _setup_ui(self):
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        if os.path.exists(crypto_utils.RAM_DISK_PATH):
            self._show_dashboard()
        else:
            self._show_login_screen()

    def _clear_ui(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

    # ==================================================================
    # ÉCRAN DE CONNEXION
    # ==================================================================

    def _show_login_screen(self):
        self._clear_ui()

        ttk.Label(
            self.main_container,
            text="🔒 SECURE VAULT ACCESS",
            style="Header.TLabel",
        ).pack(pady=(0, 20))
        ttk.Label(
            self.main_container,
            text="Authentification Double Facteur Requise (Quorum)",
            style="SubHeader.TLabel",
        ).pack(pady=(0, 20))

        login_frame = tk.Frame(
            self.main_container,
            bg=self.colors["panel"], padx=20, pady=20, relief="flat",
        )
        login_frame.pack(fill="x", padx=50)

        # Section Technique (lignes 0-2)
        self._create_auth_section(
            login_frame, "Responsable TECHNIQUE",
            self.role_tech, self.usb_path_tech, "pass_entry_tech", start_row=0,
        )

        # Séparateur
        tk.Frame(login_frame, height=2, bg=self.colors["input"]).grid(
            row=3, column=0, columnspan=2, sticky="ew", pady=15,
        )

        # Section Juridique (lignes 4-6)
        self._create_auth_section(
            login_frame, "Responsable JURIDIQUE",
            self.role_jur, self.usb_path_jur, "pass_entry_jur", start_row=4,
        )

        # Bouton déverrouillage
        tk.Button(
            self.main_container,
            text="🔓 DÉVERROUILLER LE COFFRE",
            bg=self.colors["success"], fg="white",
            font=("Helvetica", 12, "bold"),
            activebackground="#66bb6a", activeforeground="white",
            relief="flat", pady=10,
            command=self._perform_unlock,
        ).pack(fill="x", padx=50, pady=30)

    def _create_auth_section(self, parent, title, role_var, usb_var, pass_attr, start_row):
        """Construit une section d'authentification (rôle + USB + mot de passe)."""
        c = self.colors

        # Titre + sélecteur de rôle
        tk.Label(
            parent, text=title,
            bg=c["panel"], fg=c["primary"], font=("Helvetica", 11, "bold"),
        ).grid(row=start_row, column=0, sticky="w", pady=(0, 10))

        role_frame = tk.Frame(parent, bg=c["panel"])
        role_frame.grid(row=start_row, column=1, sticky="e")

        tk.Radiobutton(
            role_frame, text="Titulaire", variable=role_var, value="MAIN",
            bg=c["panel"], fg="white", selectcolor="#616161", activebackground=c["panel"],
        ).pack(side="left", padx=5)
        tk.Radiobutton(
            role_frame, text="Suppléant", variable=role_var, value="REP",
            bg=c["panel"], fg="white", selectcolor="#616161", activebackground=c["panel"],
        ).pack(side="left", padx=5)

        # Sélection fichier USB
        tk.Button(
            parent, text="📂 Fichier Clé (.bin)",
            command=lambda: self._select_file(usb_var),
        ).grid(row=start_row + 1, column=0, sticky="w", pady=5)

        tk.Label(
            parent, textvariable=usb_var,
            bg=c["panel"], fg="#bdbdbd", width=40, anchor="w",
        ).grid(row=start_row + 1, column=1, sticky="ew", pady=5)

        # Mot de passe
        tk.Label(
            parent, text="Phrase de Passe :",
            bg=c["panel"], fg="white",
        ).grid(row=start_row + 2, column=0, sticky="w", pady=5)

        entry = ttk.Entry(parent, show="*", width=30)
        entry.grid(row=start_row + 2, column=1, sticky="e", pady=5)
        setattr(self, pass_attr, entry)

    # ==================================================================
    # DASHBOARD
    # ==================================================================

    def _show_dashboard(self):
        self._clear_ui()

        # Barre supérieure
        top_bar = tk.Frame(self.main_container, bg=self.colors["success"], height=60)
        top_bar.pack(fill="x", pady=(0, 20))

        tk.Label(
            top_bar, text="🛡️ SYSTÈME OPÉRATIONNEL",
            bg=self.colors["success"], fg="white", font=("Helvetica", 14, "bold"),
        ).pack(side="left", padx=20, pady=10)

        tk.Button(
            top_bar, text="Déconnexion (Secure Wipe)",
            bg=self.colors["danger"], fg="white", font=("Helvetica", 10, "bold"),
            relief="flat", padx=15, command=self._logout,
        ).pack(side="right", padx=20, pady=10)

        # Onglets
        notebook = ttk.Notebook(self.main_container)
        notebook.pack(fill="both", expand=True)

        tab_ops = ttk.Frame(notebook)
        notebook.add(tab_ops, text="  Opérations Courantes  ")
        self._build_ops_tab(tab_ops)

        tab_admin = ttk.Frame(notebook)
        notebook.add(tab_admin, text="  Administration & Sécurité  ")
        self._build_admin_tab(tab_admin)

    def _build_ops_tab(self, parent):
        """Panneau des opérations CRUD."""
        paned = ttk.PanedWindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        left = tk.Frame(paned, bg=self.colors["panel"], padx=20, pady=20)
        right = tk.Frame(paned, bg=self.colors["bg"], padx=20, pady=20)
        paned.add(left, weight=1)
        paned.add(right, weight=2)

        # Champs de saisie
        ttk.Label(left, text="Nom du Client", background=self.colors["panel"]).pack(anchor="w", pady=(0, 5))
        self.entry_name = ttk.Entry(left, width=30)
        self.entry_name.pack(fill="x", pady=(0, 15))

        ttk.Label(left, text="Numéro de Carte (pour Ajout)", background=self.colors["panel"]).pack(anchor="w", pady=(0, 5))
        self.entry_card = ttk.Entry(left, width=30)
        self.entry_card.pack(fill="x", pady=(0, 20))

        # Boutons d'action
        ttk.Button(left, text="🔍 Rechercher", style="Primary.TButton", command=self._action_search).pack(fill="x", pady=5)
        ttk.Button(left, text="➕ Ajouter",    style="Success.TButton", command=self._action_add).pack(fill="x", pady=5)
        ttk.Button(left, text="🗑️ Supprimer",  style="Danger.TButton",  command=self._action_delete).pack(fill="x", pady=5)

        # Zone de résultat
        ttk.Label(right, text="Résultat de l'opération :", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 10))
        self.result_text = tk.Text(
            right, height=15,
            bg=self.colors["input"], fg="white",
            relief="flat", padx=10, pady=10, font=("Consolas", 10),
        )
        self.result_text.pack(fill="both", expand=True)

    def _build_admin_tab(self, parent):
        """Panneau d'administration (révocation)."""
        warn_frame = tk.Frame(parent, bg="#d32f2f", padx=20, pady=20)
        warn_frame.pack(fill="x", padx=50, pady=30)

        tk.Label(warn_frame, text="⚠️ ZONE DANGER", bg="#d32f2f", fg="white",
                 font=("Helvetica", 16, "bold")).pack()
        tk.Label(warn_frame,
                 text="La révocation est une opération irréversible qui détruit les slots d'accès.",
                 bg="#d32f2f", fg="white").pack()

        tk.Button(
            parent, text="☠️ LANCER PROCÉDURE DE RÉVOCATION",
            bg=self.colors["danger"], fg="white", font=("Helvetica", 14, "bold"),
            pady=15, command=self._open_revocation_dialog,
        ).pack(padx=20, pady=20)

        info = (
            "Protocole de Régénération Complète (Rapport §4.2) :\n"
            "  1. Sélection de l'acteur à révoquer.\n"
            "  2. Double confirmation irréversible.\n"
            "  3. Authentification de TOUS les acteurs survivants.\n"
            "  4. Génération d'une nouvelle Master Key (rotation).\n"
            "  5. Ré-chiffrement de la base de données.\n"
            "  6. Reconstruction des slots survivants uniquement."
        )
        tk.Label(parent, text=info, bg=self.colors["bg"], fg="#bdbdbd",
                 justify="left", font=("Helvetica", 10)).pack(padx=50)

    # ==================================================================
    # LOGIQUE : AUTHENTIFICATION
    # ==================================================================

    def _select_file(self, var_store):
        filename = filedialog.askopenfilename(
            initialdir=".", title="Sélectionner Clé USB",
            filetypes=(("Fichiers Clés", "*.bin"), ("Tous", "*.*")),
        )
        if filename:
            var_store.set(filename)

    def _perform_unlock(self):
        """Authentification multi-facteurs avec déchiffrement du slot."""
        # Vérification anti-bruteforce
        if self.auth_failures >= MAX_AUTH_FAILURES:
            messagebox.showerror(
                "Verrouillé",
                f"Trop de tentatives échouées ({MAX_AUTH_FAILURES}). Redémarrez l'application.",
            )
            audit.log_event("AUTH_LOCKOUT", "GUI", f"{self.auth_failures} échecs consécutifs.")
            return

        try:
            # 1. Chargement du Vault
            if not os.path.exists("vault.json"):
                raise FileNotFoundError("Vault introuvable. Exécutez setup.py.")

            with open("vault.json", "r") as f:
                vault = json.load(f)
            salt = bytes.fromhex(vault["global_salt"])

            # 2. Dérivation des parts
            part_a = crypto_utils.derive_part(
                self.pass_entry_tech.get(), self.usb_path_tech.get(), salt,
            )
            part_b = crypto_utils.derive_part(
                self.pass_entry_jur.get(), self.usb_path_jur.get(), salt,
            )

            # 3. Détermination du slot (mapping dict)
            rt, rj = self.role_tech.get(), self.role_jur.get()
            target_slot_id = SLOT_MAP.get((rt, rj))
            if target_slot_id is None:
                raise ValueError("Combinaison de rôles invalide.")

            target_slot = next(
                (s for s in vault["slots"] if s["slot_id"] == target_slot_id),
                None,
            )
            if not target_slot:
                raise ValueError(
                    f"Slot #{target_slot_id} désactivé ou introuvable (accès révoqué ?).",
                )

            # 4. Calcul KEK & déchiffrement
            kek = crypto_utils.compute_kek(part_a, part_b)
            aesgcm = AESGCM(kek)
            master_key = aesgcm.decrypt(
                bytes.fromhex(target_slot["nonce"]),
                bytes.fromhex(target_slot["ciphertext"]),
                None,
            )

            # 5. Écriture en RAM volatile
            crypto_utils.store_master_key(master_key)

            # 6. Nettoyage des secrets de l'interface
            self.pass_entry_tech.delete(0, tk.END)
            self.pass_entry_jur.delete(0, tk.END)
            self.usb_path_tech.set("")
            self.usb_path_jur.set("")

            # 7. Nettoyage des variables cryptographiques
            del master_key, kek, part_a, part_b

            # 8. Audit & transition
            self.auth_failures = 0
            audit.log_event(
                "AUTH_GUI_SUCCESS",
                f"Slot {target_slot_id}",
                f"Ouverture Dashboard ({target_slot['description']})",
            )
            self._show_dashboard()

        except Exception as e:
            self.auth_failures += 1
            # Nettoyage des champs même en cas d'échec
            self.pass_entry_tech.delete(0, tk.END)
            self.pass_entry_jur.delete(0, tk.END)

            messagebox.showerror(
                "Échec Authentification",
                f"Accès Refusé : {e}\n\n"
                f"Tentatives restantes : {MAX_AUTH_FAILURES - self.auth_failures}",
            )
            audit.log_event("AUTH_FAIL", "GUI", str(e))

    def _logout(self):
        """Déconnexion avec effacement sécurisé (Zeroization — FIPS 140-3 §7.7)."""
        crypto_utils.secure_wipe_ram()
        audit.log_event("LOGOUT", "GUI", "Déconnexion et Purge RAM (Secure Wipe)")
        self._show_login_screen()

    # ==================================================================
    # LOGIQUE : OPÉRATIONS CRUD
    # ==================================================================

    def _action_search(self):
        self._run_db_action("SEARCH")

    def _action_add(self):
        self._run_db_action("ADD")

    def _action_delete(self):
        self._run_db_action("DELETE")

    def _run_db_action(self, action: str):
        """Exécute une opération sur la base de données chiffrée."""
        try:
            mk = crypto_utils.get_master_key()
            db = crypto_utils.load_database(mk)
            name = self.entry_name.get().strip()

            if not name:
                messagebox.showwarning("Attention", "Veuillez saisir un nom.")
                return

            result = ""

            if action == "SEARCH":
                val = db.get(name)
                if val:
                    # Masquage PAN (PCI-DSS v4.0 §3.4 — seuls les 4 derniers chiffres)
                    raw = val.replace(" ", "").replace("-", "")
                    masked = "*" * (len(raw) - 4) + raw[-4:] if len(raw) >= 4 else "****"
                    result = f"✅ Trouvé : {name} => {masked}"
                else:
                    result = f"❌ Inconnu : '{name}'"
                audit.log_event("DATA_READ", "GUI_USER", f"Recherche {name}")

            elif action == "ADD":
                card = self.entry_card.get().strip()
                if not card:
                    messagebox.showwarning("Attention", "Numéro de carte requis.")
                    return

                # Validation du numéro de carte
                card_digits = card.replace(" ", "").replace("-", "")
                if not card_digits.isdigit():
                    messagebox.showwarning("Format invalide", "Le numéro ne doit contenir que des chiffres.")
                    return
                if not (13 <= len(card_digits) <= 19):
                    messagebox.showwarning("Format invalide", "Le numéro doit contenir entre 13 et 19 chiffres.")
                    return

                # Vérification de doublon (protection contre écrasement silencieux)
                if name in db:
                    overwrite = messagebox.askyesno(
                        "Doublon détecté",
                        f"'{name}' existe déjà dans la base.\n"
                        f"Voulez-vous écraser l'enregistrement existant ?",
                    )
                    if not overwrite:
                        return

                db[name] = card
                crypto_utils.save_database(db, mk)
                result = f"💾 Enregistré : {name}"
                self.entry_name.delete(0, tk.END)
                self.entry_card.delete(0, tk.END)
                audit.log_event("DATA_WRITE", "GUI_USER", f"Ajout {name}")

            elif action == "DELETE":
                if name in db:
                    del db[name]
                    crypto_utils.save_database(db, mk)
                    result = f"🗑️ Supprimé : {name}"
                    audit.log_event("DATA_DELETE", "GUI_USER", f"Suppression {name}")
                else:
                    result = f"❌ '{name}' n'existe pas dans la base."

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"[{action}] {result}\n")

        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    # ==================================================================
    # LOGIQUE : RÉVOCATION
    # ==================================================================

    def _open_revocation_dialog(self):
        """
        Procédure de révocation avec régénération complète du coffre (Rapport §4.2).

        Protocole de Régénération par Quorum :
            1. Sélection de la cible.
            2. Analyse du Vault et identification des slots impliqués.
            3. Double confirmation irréversible.
            4. Collecte des secrets de TOUS les acteurs survivants.
            5. Rotation de la Master Key.
            6. Ré-chiffrement de la base de données.
            7. Reconstruction du Vault avec les slots survivants uniquement.
        """
        # 1. Sélection de la cible
        target_choice = simpledialog.askinteger(
            "Révocation",
            "Qui révoquer ?\n\n"
            "  1. Resp. Technique (Titulaire)\n"
            "  2. Resp. Juridique (Titulaire)\n"
            "  3. Rep. Technique (Suppléant)\n"
            "  4. Rep. Juridique (Suppléant)\n\n"
            "Choix (1-4) :",
        )

        if target_choice not in REVOCATION_MAP:
            messagebox.showwarning("Annulé", "Choix invalide ou annulé.")
            return

        target_role = REVOCATION_MAP[target_choice]

        # 2. Analyse du Vault
        try:
            if not os.path.exists("vault.json"):
                raise FileNotFoundError("Vault introuvable.")

            with open("vault.json", "r") as f:
                vault = json.load(f)

            salt = bytes.fromhex(vault["global_salt"])
            initial_count = len(vault["slots"])

            # Slots survivants (par définition structurelle)
            surviving_slot_defs = [
                sd for sd in SLOT_DEFINITIONS
                if sd["tech"] != target_role and sd["jur"] != target_role
            ]
            deleted_count = initial_count - len(surviving_slot_defs)

            if deleted_count == 0:
                messagebox.showinfo(
                    "Information",
                    f"Aucun slot trouvé pour '{target_role}'. Déjà révoqué ?",
                )
                return

            # Acteurs survivants (dédupliqués)
            surviving_actors = set()
            for sd in surviving_slot_defs:
                surviving_actors.add(sd["tech"])
                surviving_actors.add(sd["jur"])

            # 3. Première confirmation
            confirm1 = messagebox.askyesno(
                "⚠️ Confirmation Requise",
                f"Vous allez RÉVOQUER : {target_role}\n\n"
                f"Slots qui seront détruits : {deleted_count}\n"
                f"Slots qui seront reconstruits : {len(surviving_slot_defs)}\n"
                f"Acteurs survivants : {', '.join(sorted(surviving_actors))}\n\n"
                f"La Master Key sera RÉGÉNÉRÉE et la base\n"
                f"de données sera RÉ-CHIFFRÉE.\n\n"
                f"Continuer ?",
            )
            if not confirm1:
                return

            # 4. Deuxième confirmation (anti-erreur)
            confirm2 = messagebox.askyesno(
                "☠️ CONFIRMATION IRRÉVERSIBLE",
                f"DERNIÈRE CHANCE.\n\n"
                f"L'acteur '{target_role}' ne pourra PLUS JAMAIS\n"
                f"accéder au système après cette opération.\n\n"
                f"Tous les acteurs survivants doivent\n"
                f"s'authentifier pour la régénération.\n\n"
                f"Confirmer la régénération définitive ?",
            )
            if not confirm2:
                return

            # 5. Collecte des secrets de TOUS les acteurs survivants
            actor_parts = {}
            for actor_name in sorted(surviving_actors):
                actor_info = ACTORS[actor_name]

                messagebox.showinfo(
                    "Authentification Requise",
                    f"Authentification de : {actor_name}\n\n"
                    f"Sélectionnez le fichier de clé USB.",
                )

                usb_path = filedialog.askopenfilename(
                    initialdir=os.path.dirname(actor_info["usb_hint"]),
                    title=f"Clé USB — {actor_name}",
                    filetypes=(("Fichiers Clés", "*.bin"), ("Tous", "*.*")),
                )
                if not usb_path:
                    messagebox.showwarning(
                        "Annulé",
                        "Révocation annulée (fichier USB manquant).",
                    )
                    return

                password = simpledialog.askstring(
                    f"Mot de Passe — {actor_name}",
                    f"Saisissez le mot de passe de :\n{actor_name}",
                    show="*",
                )
                if not password:
                    messagebox.showwarning(
                        "Annulé",
                        "Révocation annulée (mot de passe manquant).",
                    )
                    return

                actor_parts[actor_name] = crypto_utils.derive_part(
                    password, usb_path, salt,
                )
                del password

            # 6. Rotation de la Master Key
            old_mk = crypto_utils.get_master_key()
            new_mk = AESGCM.generate_key(bit_length=256)

            # 7. Ré-chiffrement de la base de données
            if os.path.exists(crypto_utils.DB_FILE):
                db = crypto_utils.load_database(old_mk)
                crypto_utils.save_database(db, new_mk)
                del db

            # 8. Reconstruction des slots survivants
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
                del kek

            # 9. Sauvegarde du Vault régénéré
            vault["slots"] = new_slots
            with open("vault.json", "w") as f:
                json.dump(vault, f, indent=4)

            # 10. Mise à jour de la MK en RAM
            crypto_utils.store_master_key(new_mk)

            # 11. Nettoyage mémoire
            del old_mk, new_mk, actor_parts

            audit.log_event(
                "REVOCATION", "GUI_ADMIN",
                f"Révocation '{target_role}' avec régénération complète. "
                f"{deleted_count} slot(s) détruit(s). "
                f"Restants : {len(new_slots)}. MK régénérée.",
            )

            messagebox.showinfo(
                "Révocation Effectuée",
                f"✅ Régénération complète réussie.\n\n"
                f"Slots détruits : {deleted_count}\n"
                f"Slots reconstruits : {len(new_slots)}\n"
                f"Master Key : RÉGÉNÉRÉE\n"
                f"Base de données : RÉ-CHIFFRÉE\n\n"
                f"L'acteur '{target_role}' est définitivement révoqué.",
            )

        except Exception as e:
            messagebox.showerror("Erreur", f"Échec de la révocation : {e}")
            audit.log_event("REVOCATION_FAIL", "GUI_ADMIN", str(e))


# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if __name__ == "__main__":
    app = SecureBankingApp()
    app.mainloop()