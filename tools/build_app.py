#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Genere coffre.py (l'application fenetre) a partir de :
  - tools/app_template.py   (le code de l'appli)
  - un fichier JSON en clair (le contenu du coffre)
  - le mot de passe maitre

Le contenu est chiffre (AES-256-CTR + HMAC, Python pur) puis embarque
dans coffre.py. Le fichier en clair n'est jamais inclus.

Usage :
  python3 tools/build_app.py <chemin_vault_clair.json> <mot_de_passe_maitre>
"""
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import aes_pure  # noqa: E402


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 tools/build_app.py <vault_clair.json> <master>")
        sys.exit(1)
    plain_path, master = sys.argv[1], sys.argv[2]

    with open(plain_path, "rb") as f:
        plaintext = f.read()
    # validation minimale
    obj = json.loads(plaintext)
    assert "categories" in obj and "entries" in obj, "JSON invalide"

    blob = aes_pure.encrypt(master, plaintext)
    data_b64 = base64.b64encode(json.dumps(blob).encode("utf-8")).decode("ascii")

    with open(os.path.join(HERE, "app_template.py"), "r", encoding="utf-8") as f:
        template = f.read()
    if "__DATA_B64__" not in template:
        print("ERREUR: marqueur __DATA_B64__ absent du template.")
        sys.exit(1)
    out = template.replace("__DATA_B64__", data_b64)

    out_path = os.path.join(ROOT, "coffre.py")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)

    kb = len(out.encode("utf-8")) / 1024
    print("coffre.py genere (%.0f Ko) — %d entrees, planning: %s" % (
        kb, len(obj["entries"]), "oui" if obj.get("planning") else "non"))


if __name__ == "__main__":
    main()
