# Procédure de Déploiement Sécurisé

## Pré-requis
* Environnement Linux sécurisé (ou WSL).
* Python 3.9+.
* Droits d'écriture dans `/dev/shm` (RAM Disk).

## Procédure d'Initialisation (Cérémonie des Clés)
1. Exécuter `python3 setup.py`.
2. Insérer les supports amovibles (Simulés dans `./usb_tech` et `./usb_juridique`).
3. Saisir les phrases de passe des responsables.
4. **Vérification** : S'assurer que le fichier `vault.json` est créé et que `master.key` n'apparaît nulle part.

## Démarrage Quotidien
1. Exécuter `python3 server.py`.
2. Choisir l'option 1.
3. Vérifier la présence de la clé volatile : `ls -l /dev/shm/secure_server_key`.