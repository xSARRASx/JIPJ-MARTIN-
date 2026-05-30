#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COFFRE - Martin   (application locale, hors-ligne)
==================================================
Ton coffre de mots de passe + ton planning, dans une vraie fenetre,
uniquement sur CET ordinateur. Rien n'est envoye sur internet.

POUR LANCER (Mac) :
  1) Installe Python depuis  https://www.python.org/downloads/  (une seule fois)
  2) Double-clique sur "coffre.command"  (ou : python3 coffre.py dans le Terminal)

Chiffrement : AES-256-CTR + HMAC-SHA256, cle derivee par PBKDF2 (250 000 tours).
Le mot de passe maitre n'est jamais stocke ; il ne sert qu'a dechiffrer en memoire.
"""
import base64
import json
import hashlib
import hmac

# ============================================================
#  Dechiffrement en Python pur (aucune dependance externe)
# ============================================================
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res


def _key_expansion(key):
    Nk, Nr = 8, 14
    words = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(words[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // Nk - 1]
        elif i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - Nk][j] ^ temp[j] for j in range(4)])
    return [sum((words[r * 4 + c] for c in range(4)), []) for r in range(Nr + 1)]


def _sub_bytes(s):
    for i in range(16):
        s[i] = _SBOX[s[i]]


def _shift_rows(s):
    n = s[:]
    for row in range(1, 4):
        for col in range(4):
            n[col * 4 + row] = s[((col + row) % 4) * 4 + row]
    s[:] = n


def _mix_columns(s):
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        s[i + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        s[i + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        s[i + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)


def _encrypt_block(rk, block):
    s = list(block)
    for i in range(16):
        s[i] ^= rk[0][i]
    for r in range(1, 14):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        for i in range(16):
            s[i] ^= rk[r][i]
    _sub_bytes(s)
    _shift_rows(s)
    for i in range(16):
        s[i] ^= rk[14][i]
    return bytes(s)


def _ctr_xor(rk, nonce, data):
    out = bytearray(len(data))
    counter = int.from_bytes(nonce, "big")
    for off in range(0, len(data), 16):
        ks = _encrypt_block(rk, counter.to_bytes(16, "big"))
        chunk = data[off:off + 16]
        for j in range(len(chunk)):
            out[off + j] = chunk[j] ^ ks[j]
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


def _decrypt(password, blob):
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ct"])
    mac = base64.b64decode(blob["mac"])
    full = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               blob.get("iterations", 250000), dklen=64)
    aes_key, mac_key = full[:32], full[32:]
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("Mot de passe incorrect.")
    return _ctr_xor(_key_expansion(aes_key), nonce, ct)


# ============================================================
#  Donnees embarquees (chiffrees)
# ============================================================
_DATA_B64 = "__DATA_B64__"
DATA = json.loads(base64.b64decode(_DATA_B64).decode("utf-8"))


def load_vault(password):
    raw = _decrypt(password, DATA)
    return json.loads(raw.decode("utf-8"))


# ============================================================
#  Interface graphique (fenetre)
# ============================================================
def main():
    import tkinter as tk
    import tkinter.font as tkfont

    BG = "#0f1422"
    BG2 = "#171d2e"
    BG3 = "#1f2740"
    FIELD = "#0b0f1d"
    ACCENT = "#7c5cff"
    ACCENT2 = "#00d4ff"
    TEXT = "#e8ecf4"
    MUTED = "#8b95a8"
    DANGER = "#ff7585"

    root = tk.Tk()
    root.title("Coffre — Martin")
    root.geometry("1080x710")
    root.minsize(900, 580)
    root.configure(bg=BG)

    mono = "Menlo" if _has_font(tkfont, "Menlo") else "Courier"
    f_title = tkfont.Font(family="Helvetica", size=22, weight="bold")
    f_h = tkfont.Font(family="Helvetica", size=15, weight="bold")
    f_n = tkfont.Font(family="Helvetica", size=11)
    f_s = tkfont.Font(family="Helvetica", size=9)
    f_mono = tkfont.Font(family=mono, size=11)

    state = {"vault": None, "view": "vault", "cat": "all", "search": ""}

    def clear(w):
        for c in w.winfo_children():
            c.destroy()

    def mkbtn(parent, text, cmd, bg=BG3, fg=TEXT, font=f_s, padx=10, pady=4):
        b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, font=font,
                      relief="flat", activebackground=ACCENT, activeforeground="white",
                      cursor="hand2", bd=0, padx=padx, pady=pady, highlightthickness=0)
        return b

    status = {"label": None}

    def flash(msg):
        if status["label"] is not None:
            status["label"].config(text=msg)
            status["label"].after(1600, lambda: status["label"].config(text="")
                                   if status["label"] else None)

    def copy(text):
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        flash("Copié ✓")

    # ---------- ECRAN DE VERROUILLAGE ----------
    def show_lock():
        clear(root)
        wrap = tk.Frame(root, bg=BG)
        wrap.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(wrap, text="🔐", bg=BG, fg=TEXT,
                 font=tkfont.Font(size=46)).pack()
        tk.Label(wrap, text="Coffre", bg=BG, fg=TEXT, font=f_title).pack(pady=(8, 0))
        tk.Label(wrap, text="Entre ton mot de passe maître", bg=BG,
                 fg=MUTED, font=f_n).pack(pady=(2, 18))
        pw = tk.Entry(wrap, show="•", width=26, font=f_n, bg=FIELD, fg=TEXT,
                      insertbackground=TEXT, relief="flat", justify="center")
        pw.pack(ipady=9)
        pw.focus_set()
        err = tk.Label(wrap, text="", bg=BG, fg=DANGER, font=f_s)

        def attempt(*_):
            try:
                v = load_vault(pw.get())
            except Exception:
                err.config(text="Mot de passe incorrect.")
                err.pack(pady=(12, 0))
                pw.delete(0, "end")
                return
            state["vault"] = v
            show_app()

        mkbtn(wrap, "Déverrouiller", attempt, bg=ACCENT, fg="white",
              font=f_h, pady=9).pack(fill="x", pady=(16, 0))
        tk.Label(wrap, text="Chiffré · hors-ligne · sur ton ordinateur",
                 bg=BG, fg=MUTED, font=f_s).pack(pady=(16, 0))
        pw.bind("<Return>", attempt)

    # ---------- APPLICATION ----------
    def show_app():
        clear(root)
        cats = {c["id"]: c for c in state["vault"]["categories"]}

        sidebar = tk.Frame(root, bg=BG2, width=240)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        main = tk.Frame(root, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        # --- entete sidebar ---
        head = tk.Frame(sidebar, bg=BG2)
        head.pack(fill="x", padx=16, pady=(16, 8))
        tk.Label(head, text="🔐  Coffre", bg=BG2, fg=TEXT, font=f_h).pack(anchor="w")
        tk.Label(head, text="MARTIN", bg=BG2, fg=MUTED, font=f_s).pack(anchor="w")

        # --- bascule Coffre / Planning ---
        sw = tk.Frame(sidebar, bg=BG2)
        sw.pack(fill="x", padx=12, pady=(4, 10))
        btn_vault = mkbtn(sw, "🔐 Coffre", lambda: switch("vault"), pady=7)
        btn_plan = mkbtn(sw, "📅 Planning", lambda: switch("planning"), pady=7)
        btn_vault.pack(side="left", expand=True, fill="x", padx=(0, 3))
        btn_plan.pack(side="left", expand=True, fill="x", padx=(3, 0))

        # --- liste des categories ---
        cat_box = tk.Listbox(sidebar, bg=FIELD, fg=TEXT, font=f_n, relief="flat",
                             selectbackground=ACCENT, selectforeground="white",
                             activestyle="none", highlightthickness=0, bd=0)
        cat_box.pack(fill="both", expand=True, padx=12, pady=4)
        cat_index = []

        def fill_categories():
            cat_box.delete(0, "end")
            cat_index.clear()
            counts = {}
            for e in state["vault"]["entries"]:
                counts[e["category"]] = counts.get(e["category"], 0) + 1
            cat_box.insert("end", "  Tout  (%d)" % len(state["vault"]["entries"]))
            cat_index.append("all")
            for c in state["vault"]["categories"]:
                n = counts.get(c["id"], 0)
                if n == 0:
                    continue
                cat_box.insert("end", "  %s  %s  (%d)" % (c.get("icon", "•"), c["name"], n))
                cat_index.append(c["id"])
            # selection courante
            if state["cat"] in cat_index:
                cat_box.selection_clear(0, "end")
                cat_box.selection_set(cat_index.index(state["cat"]))

        def on_cat(_=None):
            sel = cat_box.curselection()
            if not sel:
                return
            state["cat"] = cat_index[sel[0]]
            render_main()

        cat_box.bind("<<ListboxSelect>>", on_cat)

        # --- pied : verrouiller ---
        foot = tk.Frame(sidebar, bg=BG2)
        foot.pack(fill="x", padx=12, pady=12)
        mkbtn(foot, "🔒  Verrouiller", lock, pady=7).pack(fill="x")

        # --- contenu principal ---
        def set_toggle_styles():
            btn_vault.config(bg=ACCENT if state["view"] == "vault" else BG3,
                             fg="white" if state["view"] == "vault" else TEXT)
            btn_plan.config(bg=ACCENT if state["view"] == "planning" else BG3,
                            fg="white" if state["view"] == "planning" else TEXT)

        def switch(view):
            state["view"] = view
            set_toggle_styles()
            render_main()

        def render_main():
            clear(main)
            set_toggle_styles()
            if state["view"] == "planning":
                cat_box.pack_forget()
                render_planning(main)
            else:
                if not cat_box.winfo_ismapped():
                    cat_box.pack(fill="both", expand=True, padx=12, pady=4, before=foot)
                render_vault(main)

        # ============ VUE COFFRE ============
        def render_vault(parent):
            top = tk.Frame(parent, bg=BG)
            top.pack(fill="x", padx=18, pady=(16, 8))
            tk.Label(top, text="🔎", bg=BG, fg=MUTED, font=f_n).pack(side="left")
            search = tk.Entry(top, font=f_n, bg=FIELD, fg=TEXT, relief="flat",
                              insertbackground=TEXT)
            search.pack(side="left", fill="x", expand=True, ipady=7, padx=(8, 8))
            search.insert(0, state["search"])
            st = tk.Label(top, text="", bg=BG, fg=ACCENT2, font=f_s)
            st.pack(side="right")
            status["label"] = st

            body = tk.Frame(parent, bg=BG)
            body.pack(fill="both", expand=True, padx=18, pady=(0, 16))

            list_frame = tk.Frame(body, bg=BG, width=300)
            list_frame.pack(side="left", fill="y")
            list_frame.pack_propagate(False)
            ent_box = tk.Listbox(list_frame, bg=FIELD, fg=TEXT, font=f_n, relief="flat",
                                 selectbackground=ACCENT, selectforeground="white",
                                 activestyle="none", highlightthickness=0, bd=0)
            ent_box.pack(fill="both", expand=True)
            ent_index = []

            detail = tk.Frame(body, bg=BG)
            detail.pack(side="left", fill="both", expand=True, padx=(16, 0))

            def filtered():
                q = state["search"].strip().lower()
                items = state["vault"]["entries"]
                if state["cat"] != "all":
                    items = [e for e in items if e.get("category") == state["cat"]]
                if q:
                    def m(e):
                        return any(q in str(e.get(k, "")).lower()
                                   for k in ("name", "username", "email", "url", "notes", "category"))
                    items = [e for e in items if m(e)]
                return sorted(items, key=lambda e: e.get("name", "").lower())

            def fill_entries():
                ent_box.delete(0, "end")
                ent_index.clear()
                for e in filtered():
                    icon = e.get("icon") or (cats.get(e["category"], {}) or {}).get("icon", "🔑")
                    ent_box.insert("end", "  %s  %s" % (icon, e.get("name", "")))
                    ent_index.append(e)
                if ent_index:
                    ent_box.selection_set(0)
                    show_entry(ent_index[0])
                else:
                    clear(detail)
                    tk.Label(detail, text="Aucune entrée", bg=BG, fg=MUTED,
                             font=f_n).pack(pady=40)

            def on_search(_=None):
                state["search"] = search.get()
                fill_entries()

            search.bind("<KeyRelease>", on_search)

            def on_entry(_=None):
                sel = ent_box.curselection()
                if sel:
                    show_entry(ent_index[sel[0]])

            ent_box.bind("<<ListboxSelect>>", on_entry)

            def add_row(parent2, label, value, secret):
                row = tk.Frame(parent2, bg=BG2)
                row.pack(fill="x", pady=4)
                tk.Label(row, text=label.upper(), bg=BG2, fg=MUTED, font=f_s).pack(
                    anchor="w", padx=12, pady=(8, 0))
                line = tk.Frame(row, bg=BG2)
                line.pack(fill="x", padx=12, pady=(0, 9))
                shown = {"v": not secret}

                def disp():
                    return value if shown["v"] else "•" * min(14, len(value))

                val = tk.Label(line, text=disp(), bg=BG2, fg=TEXT, font=f_mono,
                               justify="left", wraplength=380, anchor="w")
                val.pack(side="left", fill="x", expand=True)
                mkbtn(line, "Copier", lambda: copy(value)).pack(side="right", padx=(4, 0))
                if secret:
                    tb = mkbtn(line, "Afficher", None)

                    def tog():
                        shown["v"] = not shown["v"]
                        val.config(text=disp())
                        tb.config(text="Masquer" if shown["v"] else "Afficher")
                    tb.config(command=tog)
                    tb.pack(side="right", padx=(4, 0))

            def show_entry(entry):
                clear(detail)
                cat = cats.get(entry.get("category"), {})
                h = tk.Frame(detail, bg=BG)
                h.pack(fill="x", pady=(0, 10))
                tk.Label(h, text=entry.get("icon") or cat.get("icon", "🔑"),
                         bg=BG, fg=TEXT, font=tkfont.Font(size=26)).pack(side="left")
                ht = tk.Frame(h, bg=BG)
                ht.pack(side="left", padx=10)
                tk.Label(ht, text=entry.get("name", ""), bg=BG, fg=TEXT,
                         font=f_h).pack(anchor="w")
                tk.Label(ht, text=cat.get("name", entry.get("category", "")),
                         bg=BG, fg=ACCENT2, font=f_s).pack(anchor="w")

                fields = tk.Frame(detail, bg=BG)
                fields.pack(fill="both", expand=True)
                rows = []
                if entry.get("email"):
                    rows.append(("Email", entry["email"], False))
                if entry.get("username"):
                    rows.append(("Identifiant", entry["username"], False))
                if entry.get("password"):
                    rows.append(("Mot de passe", entry["password"], True))
                if entry.get("url"):
                    rows.append(("Lien", entry["url"], False))
                for ex in entry.get("extra", []):
                    rows.append((ex.get("label", ""), ex.get("value", ""),
                                 bool(ex.get("secret"))))
                if entry.get("notes"):
                    rows.append(("Notes", entry["notes"], False))
                for (lb, vv, sc) in rows:
                    add_row(fields, lb, vv, sc)

            fill_entries()

        # ============ VUE PLANNING ============
        def render_planning(parent):
            p = state["vault"].get("planning")
            head2 = tk.Frame(parent, bg=BG)
            head2.pack(fill="x", padx=18, pady=(16, 6))
            tk.Label(head2, text="📅  %s" % (p.get("title", "Planning") if p else "Planning"),
                     bg=BG, fg=TEXT, font=f_title).pack(anchor="w")
            st = tk.Label(head2, text="", bg=BG, fg=ACCENT2, font=f_s)
            st.pack(anchor="w")
            status["label"] = st
            if not p:
                tk.Label(parent, text="Pas de planning.", bg=BG, fg=MUTED,
                         font=f_n).pack(pady=30)
                return
            if p.get("daily"):
                banner = tk.Frame(parent, bg=BG3)
                banner.pack(fill="x", padx=18, pady=(0, 10))
                tk.Label(banner, text="🔁 TOUS LES JOURS", bg=BG3, fg=MUTED,
                         font=f_s).pack(anchor="w", padx=12, pady=(8, 2))
                tags = " · ".join("%s %s" % (d.get("icon", ""), d.get("label", ""))
                                  for d in p["daily"])
                tk.Label(banner, text=tags, bg=BG3, fg=TEXT, font=f_n,
                         wraplength=760, justify="left").pack(anchor="w", padx=12,
                                                              pady=(0, 10))
            # zone defilante
            canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
            sb = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
            inner = tk.Frame(canvas, bg=BG)
            inner.bind("<Configure>",
                       lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            win = canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
            canvas.configure(yscrollcommand=sb.set)
            canvas.pack(side="left", fill="both", expand=True, padx=(18, 0), pady=(0, 16))
            sb.pack(side="right", fill="y")

            for day in p.get("days", []):
                card = tk.Frame(inner, bg=BG2)
                card.pack(fill="x", pady=5, padx=(0, 14))
                bar = tk.Frame(card, bg=day.get("color", ACCENT), height=4)
                bar.pack(fill="x")
                tk.Label(card, text=day.get("name", "").upper(), bg=BG2, fg=TEXT,
                         font=f_h).pack(anchor="w", padx=14, pady=(10, 4))
                for t in day.get("tasks", []):
                    tk.Label(card, text="   %s  %s" % (t.get("icon", "•"), t.get("label", "")),
                             bg=BG2, fg=TEXT, font=f_n, anchor="w").pack(
                        fill="x", padx=14, pady=2)
                tk.Frame(card, bg=BG2, height=8).pack()

        # init
        fill_categories()
        switch("vault")

    def lock():
        state["vault"] = None
        show_lock()

    show_lock()
    root.mainloop()


def _has_font(tkfont, name):
    try:
        return name in tkfont.families()
    except Exception:
        return False


if __name__ == "__main__":
    main()
