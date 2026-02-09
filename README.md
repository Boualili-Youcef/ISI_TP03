# Coffre-Fort Numerique -- Serveur de Paiement Securise

Proof of Concept (PoC) d'un serveur de gestion de donnees bancaires
conforme aux exigences du GIE Cartes Bancaires. Le systeme garantit la
confidentialite des numeros de cartes stockes grace a un chiffrement
multi-acteurs ou aucune personne seule ne peut acceder aux donnees.

---

## Objectifs de Securite

| Objectif                          | Mesure implementee                                      |
| :-------------------------------- | :------------------------------------------------------ |
| Confidentialite des donnees       | Chiffrement AES-256-GCM (Authenticated Encryption)      |
| Non-persistance de la cle maitre  | Stockage exclusif en RAM volatile (`/dev/shm`)          |
| Double controle obligatoire       | Quorum de deux responsables (Technique + Juridique)      |
| Authentification forte            | Deux facteurs par acteur (mot de passe + cle USB)        |
| Integrite des donnees             | Tag GCM verifie a chaque dechiffrement                   |
| Resistance au brute-force         | Argon2id (memory-hard KDF, 256 MiB)                     |
| Imputabilite                      | Journalisation SIEM-compatible de chaque operation       |
| Revocation sans partage de secret | Destruction de slots par consensus (Quorum)              |

## Fonctionnalites

### Services conformes au cahier des charges

| Service | Description                              | Interface       |
| :-----: | :--------------------------------------- | :-------------- |
|  1.v    | Initialisation du coffre (Ceremonie)     | `setup.py`      |
|  1.i    | Mise en service (Deverrouillage)         | CLI / GUI       |
|  1.ii   | Ajout d'une paire (nom, numero de carte) | CLI / GUI       |
|  1.iii  | Suppression d'une paire                  | CLI / GUI       |
|  1.iv   | Recherche d'un numero de carte           | CLI / GUI       |
|  1.vi   | Revocation d'un acteur (Repudiation)     | CLI / GUI       |

### Caracteristiques supplementaires

- Architecture Multi-Slots : 4 combinaisons d'acces (2 titulaires + 2 suppleants).
- Masquage PAN : les numeros de carte ne sont jamais affiches en entier (PCI-DSS v4.0 3.4).
- Protection anti-bruteforce : verrouillage apres 5 echecs consecutifs (GUI).
- Effacement securise : zeroization FIPS 140-3 (3 passes) a la deconnexion.
- Audit complet : rotation automatique des logs, sanitization anti-injection.

## Architecture Generale

```
setup.py            Ceremonie d'initialisation (enrolement des acteurs)
server.py           Console interactive (CLI)
gui_app.py          Interface graphique (Tkinter)
crypto_utils.py     Module cryptographique central (Argon2id, AES-GCM, Wipe)
audit.py            Journalisation SIEM-compatible
vault.json          Coffre chiffre (genere par setup.py)
cards.db.enc        Base de donnees chiffree (generee a l'usage)
```

## Pre-requis

- Python 3.9 ou superieur.
- Systeme Linux avec acces a `/dev/shm` (RAM Disk tmpfs).
- WSL est supporte pour les environnements Windows.

## Installation

```bash
# Cloner le depot
git clone <url-du-depot>
cd ISI_TP03

# Creer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dependances
pip install -r REQUIREMENTS.txt
```

## Utilisation

### 1. Initialisation du coffre (une seule fois)

```bash
python3 setup.py
```

Cette commande lance la Ceremonie des Cles :
- Generation des fichiers de cle USB pour les 4 acteurs.
- Saisie et validation des mots de passe (12 caracteres minimum, complexite imposee).
- Creation du fichier `vault.json` contenant les 4 slots chiffres.

Les dossiers `usb_tech_main/`, `usb_tech_rep/`, `usb_jur_main/`, `usb_jur_rep/`
simulent les supports amovibles. En production, ces fichiers doivent etre stockes
sur des cles USB physiques conservees dans un coffre-fort.

### 2. Demarrage du serveur

#### Mode console (CLI)

```bash
python3 server.py
```

#### Mode interface graphique

```bash
python3 gui_app.py
```

### 3. Deverrouillage

Deux responsables doivent s'authentifier simultanement :
1. Selectionner le role (Titulaire ou Suppleant) pour chaque domaine.
2. Fournir le chemin vers le fichier de cle USB (`.bin`).
3. Saisir le mot de passe.

### 4. Operations courantes

Une fois le coffre deverrouille :
- **Ajouter** : saisir un nom et un numero de carte (13 a 19 chiffres).
- **Rechercher** : saisir un nom pour afficher le numero masque.
- **Supprimer** : saisir un nom pour retirer l'enregistrement.

### 5. Revocation

La destruction des droits d'un acteur se fait par consensus :
1. Un binome valide doit s'authentifier.
2. L'acteur cible est selectionne.
3. Les slots impliquant cet acteur sont detruits.
4. Double confirmation requise (GUI).

## Limitations connues

| Limitation                                 | Justification                                                         |
| :----------------------------------------- | :-------------------------------------------------------------------- |
| Base de donnees en dict Python (nom = cle) | PoC — en production, utiliser un SGBD avec cle primaire UUID.         |
| Cles USB simulees par des dossiers locaux  | PoC — en production, utiliser de vrais supports amovibles chiffres.   |
| Pas de gestion de sessions concurrentes    | Mono-utilisateur par conception (acces physique requis).              |
| Pas de HSM materiel                        | PoC — en production, deleguer la gestion des cles a un HSM certifie. |
| Effacement memoire best-effort             | Python ne garantit pas la zeroization via le garbage collector.       |
| Revocation simplifiee (suppression de slots)| PoC — le rapport decrit une regeneration complete non implementee.   |

## Conformite et standards de reference

| Standard                    | Sections couvertes            | Application dans le projet                            |
| :-------------------------- | :---------------------------- | :---------------------------------------------------- |
| PCI-DSS v4.0                | 3.3, 3.4, 3.5, 8.3, 10       | Chiffrement, masquage PAN, gestion des cles, audit    |
| NIST SP 800-57              | Key Management                | Cycle de vie des cles, Key Wrapping                   |
| NIST SP 800-63B             | 5.1.1.2                       | Politique de mots de passe, liste noire                |
| NIST SP 800-131A            | Algorithmes approuves          | AES-256, longueurs de cle                             |
| FIPS 140-3                  | 7.7                           | Zeroization des secrets en memoire                    |
| OWASP Password Storage 2024 | Argon2id                      | Parametres de derivation (t=3, m=256MiB, p=4)         |
| RFC 9106                    | Argon2                        | Specification de l'algorithme                         |

