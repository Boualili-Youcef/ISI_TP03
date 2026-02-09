# Documentation Technique -- Coffre-Fort Numerique

Ce document detaille les choix cryptographiques, le modele de menace
et les mecanismes de securite implementes dans le PoC.

---

## 1. Modele de menace

### 1.1. Actifs proteges

| Actif                     | Classification | Localisation              |
| :------------------------ | :------------- | :------------------------ |
| Numeros de carte bancaire | PCI-DSS Scope  | `cards.db.enc` (disque)   |
| Master Key                | Secret critique | `/dev/shm` (RAM volatile) |
| Cles USB (keyfiles)       | Secret physique | Supports amovibles        |
| Mots de passe             | Secret memorise | Jamais persiste           |
| Logs d'audit              | Donnee sensible | `secure_audit.log`        |

### 1.2. Attaquants consideres

| Attaquant                  | Capacite                                   | Mitigation                                  |
| :------------------------- | :----------------------------------------- | :------------------------------------------ |
| Vol de disque dur          | Acces au filesystem complet                | MK jamais sur disque, AES-256-GCM           |
| Administrateur malveillant | Acces root au serveur                      | Quorum obligatoire, MK en RAM uniquement    |
| Responsable corrompu       | Possede ses propres facteurs               | KEK = XOR de 2 parts, 1 seule est inutile   |
| Attaque par brute-force    | Tentatives massives de mots de passe       | Argon2id (256 MiB, 3 iterations)            |
| Attaque GPU/ASIC           | Materiel specialise                        | Argon2id memory-hard (resistance GPU)        |
| Injection de logs          | Insertion de fausses entrees d'audit       | Sanitization CRLF, ANSI, null bytes          |
| Cold boot / memory dump    | Lecture de la RAM physique                 | Zeroization 3 passes, /dev/shm volatil      |

### 1.3. Hors perimetre (PoC)

- Attaque par canal auxiliaire materiel (timing, EM).
- Compromission simultanee de tous les acteurs.
- Backdoor dans l'interpreteur Python ou l'OS.
- Attaque reseau (le serveur est local, pas d'ecoute socket).

---

## 2. Primitives cryptographiques

### 2.1. Derivation de cle -- Argon2id

| Parametre      | Valeur   | Reference                       |
| :------------- | :------- | :------------------------------ |
| Variante       | Argon2id | RFC 9106, section 4             |
| Iterations (t) | 3        | OWASP Password Storage 2024     |
| Memoire (m)    | 256 MiB  | OWASP first recommendation      |
| Parallelisme (p)| 4       | RFC 9106 RECOMMENDED            |
| Longueur sortie| 32 bytes | AES-256 key length              |
| Sel            | 16 bytes | CSPRNG (`os.urandom`)           |

**Justification du choix d'Argon2id sur PBKDF2 :**

- PBKDF2-HMAC-SHA256 est vulnerable aux attaques GPU (low memory footprint).
- Argon2id combine resistance side-channel (Argon2i) et resistance GPU (Argon2d).
- Le parametre memoire (256 MiB) rend le brute-force GPU economiquement non viable.

**Chaine de derivation :**

```
Part_i = Argon2id(Password_i, Salt, t=3, m=256MiB, p=4) XOR USB_Key_i
KEK    = Part_A XOR Part_B
MK     = AES-256-GCM-Decrypt(vault.slots[slot_id].ciphertext, KEK, nonce)
```

### 2.2. Chiffrement -- AES-256-GCM

| Parametre       | Valeur    | Reference                    |
| :-------------- | :-------- | :--------------------------- |
| Algorithme      | AES-256   | NIST SP 800-131A             |
| Mode            | GCM       | NIST SP 800-38D              |
| Taille de cle   | 256 bits  | PCI-DSS v4.0 3.5             |
| Nonce           | 96 bits   | GCM standard (NIST)          |
| Tag             | 128 bits  | Integre au ciphertext        |

**Proprietes de securite :**

- **Confidentialite** : chiffrement par bloc en mode compteur.
- **Integrite + Authenticite** : tag GCM (GMAC) verifie avant toute lecture.
- **Anti-rejeu** : nonce regenere aleatoirement a chaque ecriture.

**Format du fichier chiffre :**

```
cards.db.enc = [Nonce (12 bytes)] + [Ciphertext + GCM Tag (16 bytes)]
```

### 2.3. Key Wrapping (Envelope Encryption)

La Master Key est stockee chiffree dans `vault.json`. Chaque slot contient :

```json
{
    "slot_id": 0,
    "description": "Titulaire Tech + Titulaire Jur",
    "nonce": "<hex 12 bytes>",
    "ciphertext": "<hex MK chiffree par KEK_slot + GCM tag>"
}
```

Le dechiffrement ne reussit que si la KEK candidate correspond exactement au slot
cible. Un tag GCM invalide provoque une exception et aucune donnee n'est revelee.

---

## 3. Gestion memoire et secrets

### 3.1. RAM Disk (`/dev/shm`)

Le fichier `/dev/shm/secure_server_key` contient la Master Key (32 bytes) pendant
la session active. Ce chemin est un tmpfs monte en RAM par le noyau Linux :

- **Volatilite** : le contenu disparait a l'extinction ou au reboot.
- **Permissions** : `0600` (lecture/ecriture proprietaire uniquement).
- **Pas de swap** : tmpfs n'est jamais echange sur disque (sauf pression memoire
  extreme avec swappiness active, hors perimetre PoC).

### 3.2. Zeroization (FIPS 140-3, section 7.7)

A la deconnexion ou a l'arret du serveur, la fonction `secure_wipe_ram()` execute :

1. **Passe 1 (Clear)** : ecriture de `0x00` sur toute la taille du fichier.
2. **Passe 2 (Complement)** : ecriture de `0xFF`.
3. **Passe 3 (Random)** : ecriture de donnees aleatoires (`os.urandom`).
4. **Suppression** : `os.remove()` du fichier.

Chaque passe est suivie de `f.flush()` et `os.fsync()` pour forcer l'ecriture
immediate au niveau du systeme de fichiers.

**Limitation connue** : Python utilise un garbage collector avec gestion automatique
de la memoire. Les objets `bytes` contenant des secrets peuvent persister en memoire
apres `del`. C'est une limitation inherente au langage, documentee dans le code.

### 3.3. Nettoyage des variables sensibles

Apres chaque authentification ou operation cryptographique, les variables contenant
des secrets sont explicitement supprimees :

```python
del master_key, kek, part_a, part_b, pass_a, pass_b
```

Dans la GUI, les champs de saisie sont vides meme en cas d'echec :

```python
self.pass_entry_tech.delete(0, tk.END)
self.pass_entry_jur.delete(0, tk.END)
```

---

## 4. Journalisation et audit

### 4.1. Format des logs

```
YYYY-MM-DD HH:MM:SS | LEVEL | HOST=<hostname> | PID=<pid> | [EVENT] USER=<ctx> | DESC=<desc>
```

### 4.2. Evenements journalises

| Categorie       | Declencheur                                |
| :-------------- | :----------------------------------------- |
| AUTH_SUCCESS     | Deverrouillage reussi (CLI)                |
| AUTH_GUI_SUCCESS | Deverrouillage reussi (GUI)                |
| AUTH_FAIL        | Echec d'authentification                   |
| AUTH_LOCKOUT     | Verrouillage apres N echecs (GUI)          |
| DATA_READ        | Recherche d'un enregistrement              |
| DATA_WRITE       | Ajout d'un enregistrement                  |
| DATA_DELETE      | Suppression d'un enregistrement            |
| REVOCATION       | Destruction de slots                       |
| LOGOUT           | Deconnexion avec zeroization               |
| SYSTEM           | Initialisation, arret serveur              |

### 4.3. Protections anti-injection

La fonction `_sanitize()` neutralise :

- `\n`, `\r` : prevention du log forging (CRLF injection).
- `|` : protection du separateur de champs SIEM.
- `\x1b` : neutralisation des sequences d'echappement ANSI.
- `\x00` : suppression des null bytes.

### 4.4. Rotation

- Taille maximale par fichier : 5 MiB.
- Nombre de fichiers de rotation : 5.
- Permissions : `0640`.

---

## 5. Politique de mots de passe

### 5.1. Criteres de complexite

| Critere                 | Exigence        | Reference              |
| :---------------------- | :-------------- | :--------------------- |
| Longueur minimale       | 12 caracteres   | PCI-DSS v4.0 8.3.6    |
| Majuscule               | >= 1            | PCI-DSS v4.0 8.3.6    |
| Minuscule               | >= 1            | PCI-DSS v4.0 8.3.6    |
| Chiffre                 | >= 1            | PCI-DSS v4.0 8.3.6    |
| Caractere special       | >= 1            | PCI-DSS v4.0 8.3.6    |
| Liste noire             | Verification    | NIST SP 800-63B 5.1.1.2|

### 5.2. Liste noire

Le PoC integre une liste de 12 mots de passe courants. En production, cette liste
doit etre remplacee par une verification contre la base HaveIBeenPwned (847M+
entries) ou un equivalent.

---

## 6. Limites et pistes d'amelioration

### 6.1. Structure de donnees

La base de donnees est un dictionnaire Python serialise en JSON (`{nom: carte}`).
Le nom du client sert de cle primaire, ce qui implique :

- **Risque de collision** : deux clients homonymes ne peuvent pas coexister.
  Une confirmation est demandee avant ecrasement.
- **Pas de schema** : aucune contrainte de type, de format ou de relation.

**Amelioration recommandee** : utiliser un identifiant unique (UUID v4) comme cle
primaire et indexer les noms separement.

### 6.2. Concurrence

Le PoC est mono-utilisateur par conception. En cas d'acces concurrent (non prevu),
les operations read-modify-write sur `cards.db.enc` ne sont pas atomiques et
pourraient entrainer une corruption de donnees.

### 6.3. HSM

En production, la Master Key devrait etre geree par un Hardware Security Module
(HSM) certifie FIPS 140-3 Level 3, eliminant la dependance a `/dev/shm` et aux
limitations du garbage collector Python.