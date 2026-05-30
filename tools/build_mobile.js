#!/usr/bin/env node
/* Génère coffre-mobile.html à partir de tools/mobile_template.html
   en injectant data.enc.json (base64) à la place de __VAULT_DATA__. */
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const tpl = fs.readFileSync(path.join(__dirname, 'mobile_template.html'), 'utf8');
const data = fs.readFileSync(path.join(root, 'data.enc.json'), 'utf8');

// Validation : le data doit être un JSON contenant les champs attendus
const blob = JSON.parse(data);
for (const k of ['salt', 'iv', 'data']) {
  if (!blob[k]) { console.error('data.enc.json invalide : champ', k, 'manquant'); process.exit(1); }
}

if (!tpl.includes('__VAULT_DATA__')) {
  console.error('Template invalide : marqueur __VAULT_DATA__ absent');
  process.exit(1);
}

const dataB64 = Buffer.from(data, 'utf8').toString('base64');
const out = tpl.replace('__VAULT_DATA__', dataB64);

const outPath = path.join(root, 'coffre-mobile.html');
fs.writeFileSync(outPath, out, 'utf8');
const kb = (Buffer.byteLength(out) / 1024).toFixed(0);
console.log(`coffre-mobile.html généré (${kb} Ko) — fonctionnalités d'édition activées.`);
