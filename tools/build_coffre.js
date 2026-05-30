#!/usr/bin/env node
/* ============================================================
   Génère coffre.py : un fichier Python autonome qui sert
   le coffre (HTML/CSS/JS + données chiffrées) en local, hors-ligne.

   - Embarque index.html / styles.css / app.js / data.enc.json en base64
   - Retire les appels externes (Google Fonts) -> 0 requête internet
   - Le déchiffrement se fait dans le navigateur (Web Crypto), en local

   Usage : node tools/build_coffre.js
   ============================================================ */

const fs = require('fs');
const path = require('path');

const root = process.cwd();
const read = (f) => fs.readFileSync(path.join(root, f));
const b64 = (buf) => Buffer.from(buf).toString('base64');

// --- index.html : on retire les liens vers Google Fonts (offline total) ---
let html = read('index.html').toString('utf8');
html = html
  .replace(/[ \t]*<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com"[^>]*>\n/, '')
  .replace(/[ \t]*<link rel="preconnect" href="https:\/\/fonts\.gstatic\.com"[^>]*>\n/, '')
  .replace(/[ \t]*<link href="https:\/\/fonts\.googleapis\.com[^>]*>\n/, '');

const B64_HTML = b64(Buffer.from(html, 'utf8'));
const B64_CSS  = b64(read('styles.css'));
const B64_JS   = b64(read('app.js'));
const B64_DATA = b64(read('data.enc.json'));

const py = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COFFRE - Martin  (version 100% locale, hors-ligne)
===================================================
Ton coffre de mots de passe + ton planning, uniquement sur CET ordinateur.
Rien n'est envoye sur internet. Aucune autre machine ne peut y acceder.

POUR LANCER (dans le Terminal, depuis le dossier du fichier) :
    python3 coffre.py

Ton coffre s'ouvre alors tout seul dans ton navigateur.
Pour le fermer : reviens dans la fenetre du Terminal et fais  Ctrl + C
"""
import base64
import http.server
import socketserver
import threading
import webbrowser
from urllib.parse import urlparse

# Fichiers du site, embarques (base64). Le contenu reste chiffre :
# le mot de passe maitre n'est demande que dans le navigateur.
FILES = {
    "/index.html": ("text/html; charset=utf-8", "${B64_HTML}"),
    "/styles.css": ("text/css; charset=utf-8", "${B64_CSS}"),
    "/app.js": ("application/javascript; charset=utf-8", "${B64_JS}"),
    "/data.enc.json": ("application/json; charset=utf-8", "${B64_DATA}"),
}

HOST = "127.0.0.1"          # 127.0.0.1 = uniquement cet ordinateur
PORTS = range(8765, 8800)   # essaie plusieurs ports si l'un est occupe


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            path = "/index.html"
        item = FILES.get(path)
        if item is None:
            self.send_error(404, "Introuvable")
            return
        ctype, data_b64 = item
        body = base64.b64decode(data_b64)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence (pas de logs dans le terminal)


def main():
    httpd = None
    port = None
    for p in PORTS:
        try:
            httpd = socketserver.TCPServer((HOST, p), Handler)
            port = p
            break
        except OSError:
            continue
    if httpd is None:
        print("Impossible de demarrer : aucun port libre entre 8765 et 8799.")
        return

    url = "http://%s:%d/index.html" % (HOST, port)
    line = "=" * 58
    print(line)
    print("  COFFRE - Martin   (local, hors-ligne)")
    print(line)
    print("  Ton coffre est ouvert ici :")
    print("     " + url)
    print("  Accessible UNIQUEMENT depuis cet ordinateur.")
    print("")
    print("  >> Pour fermer le coffre : Ctrl + C ici.")
    print(line)

    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\\n  Coffre ferme. A bientot.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
`;

fs.writeFileSync(path.join(root, 'coffre.py'), py, 'utf8');
const kb = (Buffer.byteLength(py) / 1024).toFixed(0);
console.log(`coffre.py généré (${kb} Ko) — autonome, hors-ligne.`);
