# 🔐 Coffre — Martin

Coffre personnel chiffré (mots de passe, clés API, comptes bancaires).
Site statique, déchiffrement en local dans le navigateur.

## 🔒 Sécurité

- **AES-256-GCM** pour le chiffrement (authentifié, ne peut pas être altéré sans détection)
- **PBKDF2-SHA256** avec **250 000 itérations** pour dériver la clé depuis ton mot de passe maître
- Sel et IV uniques générés aléatoirement à chaque sauvegarde
- Le mot de passe maître **ne quitte jamais ton navigateur**
- Le fichier `data.enc.json` contient uniquement du chiffré ; sans le mot de passe maître, c'est illisible
- Verrouillage automatique après 15 min d'inactivité

## 🚀 Mettre le site en ligne

1. Sur GitHub : **Settings → Pages**
2. Source : `Deploy from a branch`
3. Branch : `main` (ou la branche actuelle) → `/ (root)`
4. Sauvegarder
5. Le site sera dispo à `https://<utilisateur>.github.io/<repo>/`

## 🛠 Mettre à jour le contenu

Le fichier `data.enc.json` est chiffré. Pour le modifier en local :

```bash
# 1. Déchiffrer le coffre vers un fichier temporaire en clair
node tools/vault.mjs decrypt "MON_MOT_DE_PASSE" > data.plain.json

# 2. Éditer data.plain.json (ce fichier est dans .gitignore, jamais commit)

# 3. Re-chiffrer
node tools/vault.mjs replace "MON_MOT_DE_PASSE" data.plain.json

# 4. Supprimer le fichier en clair
rm data.plain.json

# 5. Commit et push uniquement data.enc.json
git add data.enc.json
git commit -m "Mise à jour du coffre"
git push
```

## 📁 Structure d'une entrée

```json
{
  "id": "unique-id",
  "name": "Nom du service",
  "category": "social",
  "icon": "📷",
  "email": "exemple@gmail.com",
  "username": "monlogin",
  "password": "...",
  "url": "https://...",
  "notes": "Notes libres",
  "extra": [
    { "label": "Code secret", "value": "...", "secret": true },
    { "label": "IBAN", "value": "FR76...", "multiline": false }
  ]
}
```

Tous les champs sauf `id`, `name` et `category` sont optionnels.
