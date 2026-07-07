#!/usr/bin/env python3
"""
==============================================================================
hids_agent.py - Agent HIDS (Host-based Intrusion Detection System)
==============================================================================

RÔLE GÉNÉRAL DE CE SCRIPT
--------------------------
Ce script tourne en permanence dans le conteneur "secops_agent" et surveille
UN SEUL fichier sensible (WATCHED_FILE). Dès qu'un évènement suspect se
produit sur ce fichier (lecture, modification, changement de droits,
exécution potentielle...), l'agent :
    1. Recalcule l'empreinte SHA-256 du fichier pour savoir si son contenu
       a réellement changé (et pas juste "on l'a regardé").
    2. Envoie une alerte JSON structurée à n8n via un webhook HTTP.
n8n se charge ensuite de router cette alerte vers Discord/Telegram/Email
et de gérer l'escalade si personne ne réagit.

L'agent peut être déclenché de 3 façons différentes (voir Contrainte 3 du
sujet) :
    - Automatiquement chaque jour à heure fixe (via APScheduler = "cron")
    - À la demande, via une requête HTTP POST sur /audit (via Flask)
    - En continu en temps réel, dès qu'un évènement système se produit sur
      le fichier (via inotify, la brique de surveillance du noyau Linux)

ARCHITECTURE INTERNE (3 threads en parallèle) :
    Thread principal  : lance le serveur Flask (API HTTP)
    Thread "scheduler": tourne en tâche de fond, gère le cron quotidien
    Thread "watcher"  : boucle infinie qui écoute les évènements inotify

Pourquoi 3 threads et pas 3 processus ? Parce qu'ils doivent tous pouvoir
lire/écrire le même fichier d'état (le dernier hash connu) sans conflit,
et Python permet de partager facilement de la mémoire entre threads grâce
à un verrou (Lock) - voir plus bas.

CORRECTIONS APPORTÉES PAR RAPPORT À LA PREMIÈRE VERSION
---------------------------------------------------------
  - Verrou thread-safe (state_lock) sur les accès au fichier d'état (hash),
    pour éviter que deux threads lisent/écrivent en même temps et faussent
    la détection d'intégrité.
  - Détection heuristique des tentatives d'exécution, car inotify ne sait
    PAS nativement distinguer une exécution d'une simple lecture (voir le
    commentaire détaillé dans classify_event()).
  - Prise en compte des sauvegardes atomiques (MOVED_TO / CREATE / DELETE)
    utilisées par des éditeurs comme vim ou nano, qui ne modifient pas le
    fichier "en place" mais le remplacent par une copie temporaire.
  - app.run(threaded=True) pour que le serveur Flask ne bloque pas pendant
    qu'un audit (calcul de hash) est en cours.
  - Authentification simple par clé API sur l'endpoint /audit, pour éviter
    que n'importe qui sur le réseau Docker puisse déclencher un audit.
"""

# --------------------------------------------------------------------------
# IMPORTS
# --------------------------------------------------------------------------
import os                                  # accès au système de fichiers, variables d'environnement
import stat                                # interprétation des permissions/métadonnées Unix (chmod, etc.)
import hashlib                             # calcul de l'empreinte cryptographique SHA-256
import threading                           # gestion des threads (watcher) + verrou (Lock)
from inotify_simple import INotify, flags  # wrapper Python autour de l'API inotify du noyau Linux
from flask import Flask, jsonify, request  # micro-framework web pour exposer l'API HTTP (mode "à la demande")
import requests                            # pour envoyer les alertes HTTP (POST) vers le webhook n8n
from datetime import datetime, timezone    # horodatage des alertes au format ISO 8601 (UTC)
from apscheduler.schedulers.background import BackgroundScheduler  # planification du cron quotidien

# --------------------------------------------------------------------------
# CONFIGURATION (toutes les valeurs sont surchargeables via variables
# d'environnement dans docker-compose.yml, pour ne rien coder en dur)
# --------------------------------------------------------------------------

# Chemin absolu du fichier à surveiller. C'est LA cible unique de l'agent.
WATCHED_FILE = os.environ.get("WATCHED_FILE", "/data/sensitive_config.txt")

# Dossier où l'agent stocke son "état interne" (ici : le dernier hash connu).
# Ce dossier doit être sur un volume Docker nommé (ext4/WSL2), pas sur /mnt/c/.
STATE_DIR = os.environ.get("STATE_DIR", "/data/state")

# Heure et minute du check-up automatique quotidien (mode CRON).
# Exemple : CRON_HOUR=2, CRON_MINUTE=0 => audit tous les jours à 02h00.
CRON_HOUR = int(os.environ.get("CRON_HOUR", 2))
CRON_MINUTE = int(os.environ.get("CRON_MINUTE", 0))

# URL du webhook n8n qui reçoit toutes les alertes de l'agent.
# "n8n_automation" est le nom du service Docker (résolu via le DNS interne
# du réseau Docker Compose - pas besoin de connaître son IP).
N8N_ALERT_WEBHOOK = os.environ.get(
    "N8N_ALERT_WEBHOOK", "http://n8n_automation:5678/webhook/hids-alert"
)

# Clé secrète attendue dans le header HTTP "X-API-Key" pour pouvoir
# déclencher un audit à la demande via POST /audit. Sans cette clé,
# n'importe quel conteneur du réseau Docker pourrait spammer l'agent.
# IMPORTANT : à définir avec une vraie valeur secrète dans docker-compose.yml,
# ne JAMAIS laisser la valeur par défaut en production.
API_KEY = os.environ.get("HIDS_API_KEY", "changeme-defini-moi-en-env")

# On s'assure que le dossier d'état existe dès le démarrage du script.
os.makedirs(STATE_DIR, exist_ok=True)

# Fichier texte qui contient une seule ligne : le dernier hash SHA-256
# connu du fichier surveillé. Sert de "mémoire" entre deux vérifications.
HASH_STATE_FILE = os.path.join(STATE_DIR, "last_known_sha256.txt")

# --------------------------------------------------------------------------
# VERROU DE CONCURRENCE (thread-safety)
# --------------------------------------------------------------------------
# Ce script fait tourner PLUSIEURS threads qui peuvent tous vouloir lire ou
# écrire HASH_STATE_FILE en même temps :
#   - le thread "watcher" (inotify), à chaque évènement sur le fichier
#   - le thread "scheduler" (cron), une fois par jour
#   - le thread principal Flask, à chaque appel POST /audit
#
# Sans protection, deux threads pourraient lire l'ancien hash en même temps,
# puis écrire chacun leur nouvelle valeur : le résultat final serait
# imprévisible (race condition) et pourrait déclencher une fausse alerte
# d'intégrité, ou au contraire en manquer une vraie.
#
# threading.Lock() garantit qu'un seul thread à la fois peut exécuter le
# bloc de code protégé par "with state_lock:". Les autres threads qui
# arrivent en même temps attendent simplement leur tour.
state_lock = threading.Lock()


# --------------------------------------------------------------------------
# UTILITAIRES : calcul de hash, gestion du fichier surveillé et de l'état
# --------------------------------------------------------------------------

def compute_sha256(path: str) -> str:
    """
    Calcule l'empreinte cryptographique SHA-256 du fichier passé en argument.

    Pourquoi SHA-256 et pas une simple comparaison de taille/date ?
    Parce qu'un attaquant peut modifier le contenu d'un fichier tout en
    remettant exactement la même date de modification (touch -d) ou la
    même taille. Le hash cryptographique, lui, change dès qu'un seul
    octet du fichier est différent : c'est la méthode de référence pour
    vérifier l'intégrité d'un fichier.

    On lit le fichier par blocs de 8192 octets (8 Ko) plutôt qu'en une
    seule fois : cela évite de charger tout le fichier en mémoire d'un
    coup si jamais il devient volumineux.

    Retourne :
        - la chaîne hexadécimale du hash (ex: "3a7bd3e2...") en cas de succès
        - None si le fichier n'existe pas ou n'est pas lisible (dans ce cas
          on logue l'erreur mais on ne fait pas planter le script)
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:  # "rb" = lecture en mode binaire, obligatoire pour hasher
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"[ERREUR] Impossible de calculer le SHA-256 ({path}): {e}")
        return None


def ensure_watched_file_exists():
    """
    Vérifie que le fichier surveillé existe bel et bien sur le disque.
    S'il est absent (premier démarrage de l'agent, ou fichier supprimé par
    un attaquant), on le recrée avec un contenu factice et des droits
    restrictifs (0o640 = lecture/écriture pour le propriétaire, lecture
    seule pour le groupe, rien pour les autres).

    Cette fonction est appelée à plusieurs endroits du script (démarrage,
    avant chaque audit) pour garantir que l'agent a toujours quelque chose
    à surveiller, même après une suppression malveillante du fichier.
    """
    if not os.path.exists(WATCHED_FILE):
        with open(WATCHED_FILE, "w") as f:
            f.write("# Fichier de configuration sensible - NE PAS MODIFIER\n")
        os.chmod(WATCHED_FILE, 0o640)
        print(f"[INFO] Fichier surveillé initialisé : {WATCHED_FILE}")


def read_last_known_hash() -> str:
    """
    Lit le dernier hash SHA-256 connu, stocké dans HASH_STATE_FILE.
    C'est cette valeur qui sert de "référence" pour savoir si le fichier
    a réellement changé entre deux vérifications.

    Protégé par state_lock (voir plus haut) pour éviter qu'un autre thread
    ne soit en train d'écrire ce même fichier au même moment.

    Retourne None si aucun hash n'a encore été enregistré (premier lancement).
    """
    with state_lock:
        if os.path.exists(HASH_STATE_FILE):
            with open(HASH_STATE_FILE) as f:
                return f.read().strip() or None
        return None


def write_last_known_hash(h: str):
    """
    Enregistre le hash SHA-256 courant comme nouvelle référence.
    Appelée après chaque audit ou chaque évènement inotify traité, pour que
    la prochaine vérification puisse comparer avec cette valeur.

    Protégée par le même verrou que read_last_known_hash() pour garantir
    qu'on ne lit/écrit jamais ce fichier de deux threads en même temps.
    """
    with state_lock:
        with open(HASH_STATE_FILE, "w") as f:
            f.write(h or "")


def send_alert_to_n8n(event_type: str, details: dict):
    """
    Construit et envoie une alerte JSON structurée vers le webhook n8n.

    C'est LE point de couture entre l'agent Python (secops_agent) et le
    moteur d'automatisation (n8n_automation). n8n reçoit ce JSON sur son
    nœud "Webhook" et déclenche ensuite tout le pipeline de diffusion
    (Discord + Telegram + Email) et la logique d'escalade à 30 minutes.

    Structure du payload envoyé :
        {
            "timestamp": "2026-07-07T10:32:00+00:00",  # horodatage UTC ISO 8601
            "watched_file": "/data/sensitive_config.txt",
            "event_type": "MODIFICATION_CONTENU",       # type d'évènement détecté
            "details": { ... }                          # infos complémentaires (hash, métadonnées...)
        }

    On utilise un timeout de 5 secondes sur la requête HTTP : si n8n est
    indisponible ou trop lent, l'agent ne doit surtout pas rester bloqué
    indéfiniment en attente de réponse (cela bloquerait la surveillance
    temps réel du fichier).

    En cas d'échec réseau, on logue l'erreur dans la console du conteneur
    mais on ne fait pas planter le script : la surveillance doit continuer
    même si l'envoi d'une alerte échoue ponctuellement.
    """
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "watched_file": WATCHED_FILE,
        "event_type": event_type,
        "details": details,
    }
    try:
        resp = requests.post(N8N_ALERT_WEBHOOK, json=payload, timeout=5)
        print(f"[ALERTE] Envoyée à n8n [{event_type}] -> HTTP {resp.status_code}")
    except requests.RequestException as e:
        print(f"[ERREUR] Echec d'envoi de l'alerte à n8n ({event_type}): {e}")


def get_file_metadata(path: str) -> dict:
    """
    Récupère les métadonnées Unix du fichier surveillé : permissions,
    propriétaire (uid/gid), bit d'exécution, taille.

    os.stat() renvoie une structure contenant toutes les infos système du
    fichier (équivalent de la commande shell `stat`). On en extrait :
        - mode_octal    : les droits d'accès au format "0o640" par exemple,
                          plus lisible que le format brut renvoyé par stat()
        - uid / gid     : identifiants numériques du propriétaire et du groupe
                          (utile pour détecter un chown suspect)
        - is_executable : True si le bit +x est positionné pour le
                          propriétaire (S_IXUSR), utilisé pour la détection
                          heuristique des tentatives d'exécution plus bas
        - size_bytes    : taille du fichier en octets

    Si le fichier a été supprimé entre-temps, on retourne un dictionnaire
    d'erreur plutôt que de laisser une exception remonter et interrompre
    l'agent.
    """
    try:
        st = os.stat(path)
        return {
            "mode_octal": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "is_executable": bool(st.st_mode & stat.S_IXUSR),
            "size_bytes": st.st_size,
        }
    except FileNotFoundError:
        return {"error": "fichier introuvable (supprimé ?)"}


def perform_full_audit(trigger_source: str = "manuel") -> dict:
    """
    Fonction centrale de l'agent : réalise un audit complet du fichier
    surveillé, quel que soit le déclencheur (cron, API HTTP, ou commande
    manuelle/Telegram relayée par n8n).

    Étapes de l'audit :
        1. S'assurer que le fichier existe (le recréer sinon).
        2. Calculer son hash SHA-256 actuel.
        3. Comparer ce hash au dernier hash connu (stocké sur disque).
        4. Récupérer les métadonnées (droits, propriétaire, taille).
        5. Déterminer si l'intégrité est respectée :
              - integrity_ok = True  si c'est le tout premier audit
                                     (previous_hash est None, rien à comparer)
                               OU si le hash actuel == le hash précédent
              - integrity_ok = False si les deux hash diffèrent : le contenu
                                     du fichier a changé depuis le dernier
                                     contrôle => c'est une alerte critique.
        6. Mettre à jour le hash de référence pour le prochain audit.
        7. Envoyer le résultat à n8n, avec un type d'évènement différent
           selon que tout est normal ("AUDIT_ROUTINE") ou qu'une anomalie
           d'intégrité est détectée ("AUDIT_INTEGRITY_MISMATCH").

    Paramètre :
        trigger_source : chaîne de texte identifiant l'origine de l'audit
                          (ex: "cron_planifie", "api_http", "telegram_bot").
                          Elle est incluse dans l'alerte pour que l'équipe
                          sache d'où vient la demande de vérification.

    Retourne un dictionnaire "result" utilisé à la fois pour la réponse
    HTTP (endpoint /audit) et pour la charge utile envoyée à n8n.
    """
    ensure_watched_file_exists()
    current_hash = compute_sha256(WATCHED_FILE)
    previous_hash = read_last_known_hash()
    metadata = get_file_metadata(WATCHED_FILE)
    integrity_ok = (previous_hash is None) or (current_hash == previous_hash)

    result = {
        "trigger_source": trigger_source,
        "sha256_current": current_hash,
        "sha256_previous": previous_hash,
        "integrity_ok": integrity_ok,
        "metadata": metadata,
    }

    if current_hash:
        write_last_known_hash(current_hash)

    print(f"[AUDIT] source={trigger_source} | integrity_ok={integrity_ok}")
    send_alert_to_n8n(
        "AUDIT_ROUTINE" if integrity_ok else "AUDIT_INTEGRITY_MISMATCH", result
    )
    return result


# --------------------------------------------------------------------------
# SURVEILLANCE TEMPS RÉEL (inotify)
# --------------------------------------------------------------------------
# inotify est un mécanisme du noyau Linux qui permet à un programme de se
# faire "prévenir" instantanément quand quelque chose se passe sur un
# fichier ou un dossier (ouverture, écriture, changement de droits...),
# sans avoir à vérifier le fichier en boucle ("polling"). C'est beaucoup
# plus efficace en performance qu'une boucle qui recalculerait le hash
# toutes les secondes.
#
# WATCH_FLAGS définit la LISTE des types d'évènements que l'on souhaite
# recevoir de la part du noyau pour le dossier contenant le fichier
# surveillé :
#   - MODIFY       : le contenu du fichier a été écrit/modifié
#   - OPEN         : le fichier a été ouvert (lecture ou écriture)
#   - ACCESS       : le contenu du fichier a été lu
#   - ATTRIB       : les métadonnées ont changé (chmod, chown, touch...)
#   - CLOSE_WRITE  : le fichier a été fermé après avoir été ouvert en écriture
#   - CLOSE_NOWRITE: le fichier a été fermé après une ouverture en lecture seule
#   - MOVED_TO / CREATE : un fichier a été créé ou déplacé DANS le dossier
#                          surveillé (cas des éditeurs qui remplacent le
#                          fichier au lieu de le modifier en place - voir
#                          plus bas)
#   - MOVED_FROM / DELETE : le fichier a été déplacé ou supprimé du dossier
WATCH_FLAGS = (
    flags.MODIFY
    | flags.OPEN
    | flags.ACCESS
    | flags.ATTRIB
    | flags.CLOSE_WRITE
    | flags.CLOSE_NOWRITE
    | flags.MOVED_TO      # capture les sauvegardes atomiques (vim, nano...)
    | flags.MOVED_FROM
    | flags.CREATE
    | flags.DELETE
)


def classify_event(event_flags: list, path: str) -> str:
    """
    Traduit une liste brute de flags inotify (souvent plusieurs flags
    combinés pour un même évènement) en UNE catégorie métier lisible,
    utilisée ensuite dans les logs et dans l'alerte envoyée à n8n.

    L'ordre des "if" est important : on teste d'abord les évènements les
    plus spécifiques/critiques (changement de droits, modification de
    contenu) avant de retomber sur les cas plus génériques (lecture simple).

    ------------------------------------------------------------------
    LIMITE TECHNIQUE IMPORTANTE — détection d'exécution
    ------------------------------------------------------------------
    inotify ne dispose PAS d'un flag natif "exécution". Concrètement, le
    noyau Linux ne fait AUCUNE différence au niveau inotify entre :
        cat sensitive_config.txt        (simple lecture)
        ./sensitive_config.txt          (tentative d'exécution)
    Les deux génèrent exactement la même séquence d'évènements :
    OPEN + ACCESS + CLOSE_NOWRITE.

    La détection fiable d'une exécution nécessiterait fanotify (avec le
    flag FAN_OPEN_EXEC_PERM) ou le sous-système auditd, qui demandent tous
    les deux des capacités noyau élevées (CAP_SYS_ADMIN) que l'on ne veut
    pas donner à un conteneur non privilégié pour des raisons de sécurité
    (donner CAP_SYS_ADMIN reviendrait presque à donner un accès root au
    conteneur, ce qui est contraire à l'esprit "moindre privilège" d'un HIDS).

    SOLUTION RETENUE ICI (heuristique, à assumer en soutenance) :
    Si le fichier possède le bit +x (exécutable) ET qu'un évènement
    d'ouverture est détecté, on le remonte comme "TENTATIVE_EXECUTION_POSSIBLE"
    plutôt que comme une simple lecture. Ce n'est pas une preuve formelle
    d'exécution, mais un signal suffisant pour alerter l'équipe dans le
    contexte de ce challenge.
    ------------------------------------------------------------------

    Paramètres :
        event_flags : liste des flags inotify bruts pour cet évènement
                      (déjà décodés depuis le masque binaire via
                      flags.from_mask() dans realtime_watch_loop())
        path        : chemin du fichier surveillé, nécessaire pour aller
                      consulter son bit d'exécution via get_file_metadata()

    Retourne une chaîne de caractères identifiant le type d'évènement.
    """
    # Cas 1 : changement des permissions ou du propriétaire (chmod/chown/touch)
    if flags.ATTRIB in event_flags:
        return "CHANGEMENT_PERMISSIONS_OU_PROPRIETAIRE"

    # Cas 2 : le contenu du fichier a été écrit puis la modification finalisée
    if flags.MODIFY in event_flags or flags.CLOSE_WRITE in event_flags:
        return "MODIFICATION_CONTENU"

    # Cas 3 : remplacement atomique du fichier (comportement typique de vim/nano :
    # ils écrivent un fichier temporaire puis le renomment à la place de l'original,
    # ce qui NE déclenche PAS de flag MODIFY classique mais un CREATE/MOVED_TO)
    if flags.MOVED_TO in event_flags or flags.CREATE in event_flags:
        return "MODIFICATION_CONTENU_VIA_REMPLACEMENT_ATOMIQUE"

    # Cas 4 : le fichier a été déplacé ailleurs ou supprimé du dossier surveillé
    if flags.DELETE in event_flags or flags.MOVED_FROM in event_flags:
        return "SUPPRESSION_OU_DEPLACEMENT"

    # Cas 5 : ouverture / lecture / copie du fichier (voir limite technique ci-dessus
    # concernant la distinction lecture vs exécution)
    if flags.OPEN in event_flags or flags.ACCESS in event_flags or flags.CLOSE_NOWRITE in event_flags:
        metadata = get_file_metadata(path)
        if metadata.get("is_executable"):
            return "TENTATIVE_EXECUTION_POSSIBLE"
        return "OUVERTURE_OU_LECTURE"

    # Cas par défaut : évènement reçu mais non couvert par les catégories ci-dessus
    return "EVENEMENT_INCONNU"


def realtime_watch_loop():
    """
    Boucle principale de surveillance temps réel. Tourne en continu dans
    un thread daemon dédié (voir la fin du script), pendant toute la durée
    de vie du conteneur.

    Fonctionnement :
        1. On s'assure que le fichier existe avant de commencer à le
           surveiller (sinon inotify n'aurait rien à observer).
        2. On crée une instance INotify() et on lui demande de surveiller
           le DOSSIER contenant le fichier (et non le fichier lui-même) :
           c'est nécessaire car certains évènements comme la suppression
           ou le remplacement atomique ne peuvent être captés qu'au niveau
           du dossier parent.
        3. Si aucun hash de référence n'existe encore (premier lancement),
           on initialise l'état avec le hash actuel du fichier.
        4. On entre dans une boucle infinie : inotify.read(timeout=None)
           est une fonction BLOQUANTE qui met le thread en pause tant
           qu'aucun évènement ne se produit (donc 0% CPU consommé en
           attente, contrairement à une boucle de polling classique).
        5. Pour chaque évènement reçu, on filtre déjà ceux qui ne
           concernent pas notre fichier cible (le dossier peut contenir
           d'autres fichiers), on classe l'évènement, on recalcule le hash,
           puis on envoie l'alerte à n8n si ce n'est pas un doublon.

    Anti-spam (variable last_logged) :
        Un seul geste utilisateur (ex: ouvrir un fichier avec `cat`) peut
        déclencher PLUSIEURS évènements inotify quasi simultanés (OPEN puis
        ACCESS puis CLOSE_NOWRITE). Pour éviter d'envoyer 3 alertes
        identiques à n8n pour une seule action réelle, on mémorise la
        dernière "signature" (type d'évènement + hash) déjà loguée, et on
        ignore les répétitions immédiates identiques.
    """
    ensure_watched_file_exists()
    inotify = INotify()
    # os.path.dirname(WATCHED_FILE) : on surveille le DOSSIER parent, pas le
    # fichier directement, car un fichier supprimé/renommé ne peut plus être
    # surveillé lui-même une fois qu'il n'existe plus.
    watch_dir = os.path.dirname(WATCHED_FILE) or "."
    inotify.add_watch(watch_dir, WATCH_FLAGS)
    print(f"[INFO] Surveillance temps réel démarrée sur : {watch_dir}")

    # Initialisation du hash de référence si c'est le tout premier démarrage
    if read_last_known_hash() is None:
        write_last_known_hash(compute_sha256(WATCHED_FILE))

    last_logged = None  # évite de spammer le même évènement identique

    while True:
        # inotify.read() est bloquant : le thread "dort" tant qu'il n'y a
        # aucun évènement, ce qui est très économe en ressources.
        for event in inotify.read(timeout=None):
            # On ne s'intéresse qu'aux évènements concernant NOTRE fichier
            # (le dossier surveillé peut contenir d'autres fichiers).
            if event.name != os.path.basename(WATCHED_FILE):
                continue

            # event.mask est un entier binaire ; flags.from_mask() le
            # décode en une liste de constantes lisibles (ex: [MODIFY, CLOSE_WRITE])
            event_flags = flags.from_mask(event.mask)
            event_type = classify_event(event_flags, WATCHED_FILE)

            # Cas particulier : le fichier a disparu entre l'évènement et
            # notre traitement (ex: suppression). On ne peut pas calculer
            # de hash sur un fichier qui n'existe plus.
            if not os.path.exists(WATCHED_FILE):
                print(f"[EVENEMENT] FICHIER_ABSENT | type_brut={event_type}")
                send_alert_to_n8n("FICHIER_SUPPRIME", {"type_brut": event_type})
                last_logged = None  # on réinitialise pour ne pas bloquer les futurs évènements
                continue

            current_hash = compute_sha256(WATCHED_FILE)
            previous_hash = read_last_known_hash()
            content_changed = current_hash != previous_hash

            # Anti-doublon : si on a déjà loggé exactement ce type
            # d'évènement avec ce même hash juste avant, on l'ignore.
            signature = (event_type, current_hash)
            if signature == last_logged:
                continue  # doublon immédiat, on ignore

            last_logged = signature
            print(f"[EVENEMENT] {event_type} | changement_effectif={content_changed} | sha256={current_hash}")

            if current_hash:
                write_last_known_hash(current_hash)

            send_alert_to_n8n(event_type, {
                "sha256_current": current_hash,
                "content_effectively_changed": content_changed,
                "metadata": get_file_metadata(WATCHED_FILE),
            })


# --------------------------------------------------------------------------
# API HTTP (mode "à la demande" - Contrainte 3, mode 2 du sujet)
# --------------------------------------------------------------------------
# Flask expose un petit serveur web permettant de déclencher un audit à
# distance, par exemple depuis n8n (quand un admin tape /run-audit sur
# Telegram) ou depuis n'importe quel outil tiers du réseau Docker.
app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    """
    Endpoint de vérification de vie ("healthcheck"). Ne nécessite aucune
    authentification car il ne renvoie aucune information sensible et sert
    uniquement à vérifier que le conteneur répond bien (utile pour
    docker-compose healthcheck, ou pour un monitoring externe).
    """
    return jsonify({"status": "ok", "watched_file": WATCHED_FILE})


@app.route("/audit", methods=["POST"])
def trigger_audit():
    """
    Endpoint principal du mode "à la demande". Toute requête POST reçue
    ici déclenche immédiatement un audit complet du fichier surveillé,
    exactement comme le ferait le cron quotidien, mais à la demande.

    Sécurité : on exige un header "X-API-Key" correspondant exactement à
    la variable d'environnement HIDS_API_KEY. Sans cette vérification,
    n'importe quel conteneur ou service ayant accès au réseau Docker
    interne pourrait déclencher des audits à volonté (déni de service
    léger, ou bruit inutile dans les alertes).

    Corps de requête JSON optionnel :
        { "source": "n8n_telegram_bot" }
    Le champ "source" permet de tracer précisément QUI a demandé cet
    audit (utile pour distinguer un déclenchement Telegram d'un simple
    test manuel avec curl). S'il est absent, on utilise "api_http" par défaut.

    Retourne le résultat complet de l'audit au format JSON avec un code
    HTTP 200 en cas de succès, ou 401 si la clé API est invalide/absente.
    """
    # Authentification simple par clé API (header X-API-Key).
    provided_key = request.headers.get("X-API-Key", "")
    if provided_key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    # get_json(silent=True) : ne lève pas d'exception si le corps n'est pas
    # du JSON valide ou est absent ; renvoie simplement None dans ce cas.
    body = request.get_json(silent=True) or {}
    source = body.get("source", "api_http")
    result = perform_full_audit(trigger_source=source)
    return jsonify(result), 200


# --------------------------------------------------------------------------
# PLANIFICATION (mode "cron" - Contrainte 3, mode 1 du sujet)
# --------------------------------------------------------------------------
def start_scheduler():
    """
    Configure et démarre APScheduler pour exécuter automatiquement un
    audit complet une fois par jour, à l'heure définie par CRON_HOUR et
    CRON_MINUTE (par défaut 02h00, une heure creuse typique pour un
    check-up de routine sans impacter la production).

    BackgroundScheduler fait tourner cette tâche dans SON PROPRE thread
    interne, en parallèle du reste du script (serveur Flask + watcher
    inotify) : les trois mécanismes coexistent sans se bloquer les uns
    les autres.

    trigger="cron" avec hour=X, minute=Y reproduit le comportement d'une
    ligne crontab classique (ex: équivalent de "0 2 * * *" pour 02h00
    tous les jours).

    kwargs={"trigger_source": "cron_planifie"} : permet de transmettre un
    argument nommé à la fonction perform_full_audit() à chaque exécution,
    pour que l'alerte générée indique clairement qu'elle vient du
    check-up automatique et non d'une demande manuelle.
    """
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        perform_full_audit,
        trigger="cron",
        hour=CRON_HOUR,
        minute=CRON_MINUTE,
        kwargs={"trigger_source": "cron_planifie"},
        id="daily_routine_audit",
    )
    scheduler.start()
    print(f"[INFO] Planificateur cron démarré : audit quotidien à {CRON_HOUR:02d}:{CRON_MINUTE:02d}")
    return scheduler


# --------------------------------------------------------------------------
# POINT D'ENTRÉE PRINCIPAL
# --------------------------------------------------------------------------
# Ce bloc ne s'exécute que si le script est lancé directement
# (ex: `python3 hids_agent.py` ou via l'ENTRYPOINT du conteneur Docker),
# et non s'il est importé comme module par un autre script.
if __name__ == "__main__":
    # 1) Démarrage du planificateur cron (tourne dans son propre thread interne)
    start_scheduler()

    # 2) Démarrage du watcher inotify dans un thread "daemon" : un thread
    # daemon s'arrête automatiquement quand le programme principal se
    # termine, on n'a donc pas besoin de le stopper explicitement.
    watcher_thread = threading.Thread(target=realtime_watch_loop, daemon=True)
    watcher_thread.start()

    # 3) Démarrage du serveur Flask en dernier, car app.run() est une
    # fonction BLOQUANTE qui garde le processus principal en vie tant que
    # le serveur tourne. Tout ce qui doit démarrer AVANT (scheduler, watcher)
    # doit donc être lancé avant cet appel.
    print("[INFO] API HTTP démarrée sur le port 8000")
    # threaded=True : permet à Flask de traiter plusieurs requêtes HTTP en
    # parallèle (ex: /health et /audit en même temps) au lieu de les traiter
    # une par une, ce qui éviterait qu'un audit long (calcul de hash) ne
    # bloque la réception d'autres requêtes entrantes.
    app.run(host="0.0.0.0", port=8000, threaded=True)
