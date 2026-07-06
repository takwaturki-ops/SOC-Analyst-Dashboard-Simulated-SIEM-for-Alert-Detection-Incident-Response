#!/usr/bin/env python3
"""
hids_agent.py - Agent HIDS (version en construction, étape 2/5)
Ajout : surveillance temps réel via inotify.
"""

import os
import stat
import hashlib
import threading
from inotify_simple import INotify, flags
from flask import Flask, jsonify, request

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
WATCHED_FILE = os.environ.get("WATCHED_FILE", "/data/sensitive_config.txt")
STATE_DIR = os.environ.get("STATE_DIR", "/data/state")

os.makedirs(STATE_DIR, exist_ok=True)

HASH_STATE_FILE = os.path.join(STATE_DIR, "last_known_sha256.txt")


def compute_sha256(path: str) -> str:
    """Calcule l'empreinte SHA-256 du fichier. Retourne None si illisible."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"[ERREUR] Impossible de calculer le SHA-256 ({path}): {e}")
        return None


def ensure_watched_file_exists():
    """Crée un fichier cible de démo s'il n'existe pas encore (1er run)."""
    if not os.path.exists(WATCHED_FILE):
        with open(WATCHED_FILE, "w") as f:
            f.write("# Fichier de configuration sensible - NE PAS MODIFIER\n")
        os.chmod(WATCHED_FILE, 0o640)
        print(f"[INFO] Fichier surveillé initialisé : {WATCHED_FILE}")


def read_last_known_hash() -> str:
    if os.path.exists(HASH_STATE_FILE):
        with open(HASH_STATE_FILE) as f:
            return f.read().strip()
    return None


def write_last_known_hash(h: str):
    with open(HASH_STATE_FILE, "w") as f:
        f.write(h or "")
def get_file_metadata(path: str) -> dict:
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
    return result

# --------------------------------------------------------------------------
# Surveillance temps réel (inotify)
# --------------------------------------------------------------------------
WATCH_FLAGS = (
    flags.MODIFY
    | flags.OPEN
    | flags.ACCESS
    | flags.ATTRIB
    | flags.CLOSE_WRITE
    | flags.CLOSE_NOWRITE
)


def classify_event(event_flags: list) -> str:
    if flags.ATTRIB in event_flags:
        return "CHANGEMENT_PERMISSIONS_OU_PROPRIETAIRE"
    if flags.MODIFY in event_flags or flags.CLOSE_WRITE in event_flags:
        return "MODIFICATION_CONTENU"
    if flags.OPEN in event_flags or flags.ACCESS in event_flags or flags.CLOSE_NOWRITE in event_flags:
        return "OUVERTURE_OU_LECTURE"
    return "EVENEMENT_INCONNU"


def realtime_watch_loop():
    ensure_watched_file_exists()
    inotify = INotify()
    watch_dir = os.path.dirname(WATCHED_FILE) or "."
    inotify.add_watch(watch_dir, WATCH_FLAGS)
    print(f"[INFO] Surveillance temps réel démarrée sur : {watch_dir}")

    if read_last_known_hash() is None:
        write_last_known_hash(compute_sha256(WATCHED_FILE))

    last_logged = None  # évite de spammer le même évènement identique

    while True:
        for event in inotify.read(timeout=None):
            if event.name != os.path.basename(WATCHED_FILE):
                continue

            event_flags = flags.from_mask(event.mask)
            event_type = classify_event(event_flags)

            if not os.path.exists(WATCHED_FILE):
                print(f"[EVENEMENT] FICHIER_ABSENT | type_brut={event_type}")
                continue

            current_hash = compute_sha256(WATCHED_FILE)
            previous_hash = read_last_known_hash()
            content_changed = current_hash != previous_hash

            signature = (event_type, current_hash)
            if signature == last_logged:
                continue  # doublon immédiat, on ignore

            last_logged = signature
            print(f"[EVENEMENT] {event_type} | changement_effectif={content_changed} | sha256={current_hash}")

            if current_hash:
                write_last_known_hash(current_hash)
# --------------------------------------------------------------------------
# API HTTP (mode "à la demande")
# --------------------------------------------------------------------------
app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "watched_file": WATCHED_FILE})


@app.route("/audit", methods=["POST"])
def trigger_audit():
    body = request.get_json(silent=True) or {}
    source = body.get("source", "api_http")
    result = perform_full_audit(trigger_source=source)
    return jsonify(result), 200


if __name__ == "__main__":
    watcher_thread = threading.Thread(target=realtime_watch_loop, daemon=True)
    watcher_thread.start()

    print("[INFO] API HTTP démarrée sur le port 8000")
    app.run(host="0.0.0.0", port=8000)
