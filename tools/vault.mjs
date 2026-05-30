#!/usr/bin/env node
/* ============================================================
   Outil CLI pour gérer le coffre chiffré.
   Compatible avec le format lu par app.js (AES-256-GCM, PBKDF2-SHA256).

   Usage :
     node tools/vault.mjs init <master>           # crée un coffre vide
     node tools/vault.mjs decrypt <master>        # affiche le contenu en JSON
     node tools/vault.mjs replace <master> <path> # remplace tout le contenu
                                                  # par le JSON du fichier
   ============================================================ */

import { promises as fs } from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

const DATA_FILE = path.resolve(process.cwd(), 'data.enc.json');
const ITERATIONS = 250000;
const KEY_LEN = 32; // 256 bits
const IV_LEN = 12;
const SALT_LEN = 16;

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, 'sha256');
}

function encrypt(password, obj) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const dataWithTag = Buffer.concat([ciphertext, authTag]);
  return {
    version: 1,
    algo: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations: ITERATIONS,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    data: dataWithTag.toString('base64'),
  };
}

function decrypt(password, blob) {
  const salt = Buffer.from(blob.salt, 'base64');
  const iv = Buffer.from(blob.iv, 'base64');
  const dataWithTag = Buffer.from(blob.data, 'base64');
  const tagStart = dataWithTag.length - 16;
  const ciphertext = dataWithTag.subarray(0, tagStart);
  const authTag = dataWithTag.subarray(tagStart);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

const DEFAULT_CATEGORIES = [
  { id: 'social',     name: 'Réseaux sociaux',    icon: '📸', color: '#ff6b9d' },
  { id: 'email',      name: 'Email',              icon: '📧', color: '#4facfe' },
  { id: 'apple',      name: 'Apple / iCloud',     icon: '🍎', color: '#a8a8a8' },
  { id: 'google',     name: 'Google / YouTube',   icon: '📺', color: '#ff4444' },
  { id: 'gaming',     name: 'Gaming',             icon: '🎮', color: '#9146ff' },
  { id: 'banking',    name: 'Banque & Finance',   icon: '🏦', color: '#00c896' },
  { id: 'phone',      name: 'Téléphonie',         icon: '📱', color: '#ff8800' },
  { id: 'admin',      name: 'Santé & Admin',      icon: '🏥', color: '#3aa8ff' },
  { id: 'streaming',  name: 'Streaming & Loisirs',icon: '🎬', color: '#e50914' },
  { id: 'ai',         name: 'IA & Outils',        icon: '🤖', color: '#7c5cff' },
  { id: 'guestlucky', name: 'GuestLucky',         icon: '🏠', color: '#ffb547' },
  { id: 'dev',        name: 'Dev & Cloud',        icon: '💻', color: '#00d4ff' },
  { id: 'other',      name: 'Autre',              icon: '📦', color: '#8b95a8' },
];

const [, , cmd, password, arg] = process.argv;

if (!cmd || !password) {
  console.error('Usage: node tools/vault.mjs <init|decrypt|replace> <master> [path]');
  process.exit(1);
}

if (cmd === 'init') {
  const vault = { categories: DEFAULT_CATEGORIES, entries: [] };
  const blob = encrypt(password, vault);
  await fs.writeFile(DATA_FILE, JSON.stringify(blob, null, 2));
  console.log(`Coffre vide créé : ${DATA_FILE}`);
} else if (cmd === 'decrypt') {
  const blob = JSON.parse(await fs.readFile(DATA_FILE, 'utf8'));
  const vault = decrypt(password, blob);
  console.log(JSON.stringify(vault, null, 2));
} else if (cmd === 'replace') {
  if (!arg) throw new Error('replace : chemin du fichier JSON requis');
  const vault = JSON.parse(await fs.readFile(arg, 'utf8'));
  if (!vault.categories || !vault.entries) {
    throw new Error('Le JSON doit avoir { categories, entries }');
  }
  const blob = encrypt(password, vault);
  await fs.writeFile(DATA_FILE, JSON.stringify(blob, null, 2));
  console.log(`Coffre mis à jour : ${vault.entries.length} entrées, ${vault.categories.length} catégories`);
} else {
  console.error(`Commande inconnue : ${cmd}`);
  process.exit(1);
}
