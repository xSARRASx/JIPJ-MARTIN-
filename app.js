/* ============================================================
   Coffre Martin — Logique frontend
   Chiffrement AES-256-GCM + PBKDF2 (250 000 itérations)
   Données déchiffrées uniquement en mémoire navigateur
   ============================================================ */

(() => {
  const DATA_FILE = 'data.enc.json';
  const PBKDF2_ITERATIONS = 250000;
  const AUTO_LOCK_MINUTES = 15;

  // --------- Crypto helpers ---------
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const b64encode = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const b64decode = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

  async function deriveKey(password, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function decryptVault(password, blob) {
    const salt = b64decode(blob.salt);
    const iv = b64decode(blob.iv);
    const ciphertext = b64decode(blob.data);
    const iterations = blob.iterations || PBKDF2_ITERATIONS;
    const key = await deriveKey(password, salt, iterations);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(dec.decode(plain));
  }

  // --------- State ---------
  const state = {
    vault: null,
    currentCategory: 'all',
    search: '',
    autoLockTimer: null,
    visiblePasswords: new Set(),
  };

  // --------- Toasts ---------
  const toastContainer = document.getElementById('toast-container');
  function toast(message, type = 'success') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    toastContainer.appendChild(el);
    setTimeout(() => el.remove(), 2000);
  }

  // --------- Clipboard ---------
  async function copy(text, label = 'Copié') {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${label} dans le presse-papier`);
    } catch {
      toast('Impossible de copier', 'error');
    }
  }

  // --------- Auto-lock ---------
  function resetAutoLock() {
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    state.autoLockTimer = setTimeout(lock, AUTO_LOCK_MINUTES * 60 * 1000);
  }

  function lock() {
    state.vault = null;
    state.visiblePasswords.clear();
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    document.getElementById('app').hidden = true;
    document.getElementById('lock-screen').style.display = '';
    const pw = document.getElementById('master-password');
    pw.value = '';
    pw.focus();
  }

  // --------- Unlock flow ---------
  const lockScreen = document.getElementById('lock-screen');
  const unlockForm = document.getElementById('unlock-form');
  const unlockError = document.getElementById('unlock-error');
  const masterInput = document.getElementById('master-password');
  const unlockBtn = unlockForm.querySelector('button[type="submit"]');

  unlockForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    unlockError.hidden = true;
    unlockBtn.disabled = true;
    unlockBtn.querySelector('.btn-label').textContent = 'Déchiffrement…';
    unlockBtn.querySelector('.btn-spinner').hidden = false;

    try {
      const res = await fetch(DATA_FILE + '?t=' + Date.now(), { cache: 'no-store' });
      if (!res.ok) throw new Error('Fichier introuvable');
      const blob = await res.json();
      const vault = await decryptVault(masterInput.value, blob);
      state.vault = vault;
      lockScreen.style.display = 'none';
      document.getElementById('app').hidden = false;
      renderAll();
      resetAutoLock();
    } catch (err) {
      console.error(err);
      unlockError.textContent = 'Mot de passe incorrect.';
      unlockError.hidden = false;
      masterInput.select();
    } finally {
      unlockBtn.disabled = false;
      unlockBtn.querySelector('.btn-label').textContent = 'Déverrouiller';
      unlockBtn.querySelector('.btn-spinner').hidden = true;
    }
  });

  // --------- Rendering ---------
  function getCategoryById(id) {
    return state.vault.categories.find(c => c.id === id);
  }

  function filteredEntries() {
    const q = state.search.trim().toLowerCase();
    let entries = state.vault.entries;
    if (state.currentCategory !== 'all') {
      entries = entries.filter(e => e.category === state.currentCategory);
    }
    if (q) {
      entries = entries.filter(e => {
        return [e.name, e.username, e.email, e.url, e.notes, e.category]
          .filter(Boolean)
          .some(v => v.toLowerCase().includes(q));
      });
    }
    return entries.sort((a, b) => a.name.localeCompare(b.name));
  }

  function renderCategories() {
    const nav = document.getElementById('categories-nav');
    const counts = { all: state.vault.entries.length };
    for (const e of state.vault.entries) {
      counts[e.category] = (counts[e.category] || 0) + 1;
    }
    const allBtn = nav.querySelector('[data-category="all"]');
    allBtn.querySelector('.category-count').textContent = counts.all;
    // remove old buttons except 'all'
    nav.querySelectorAll('.category-item:not([data-category="all"])').forEach(n => n.remove());
    for (const cat of state.vault.categories) {
      const btn = document.createElement('button');
      btn.className = 'category-item' + (cat.id === state.currentCategory ? ' active' : '');
      btn.dataset.category = cat.id;
      btn.innerHTML = `
        <span class="category-icon">${cat.icon || '📁'}</span>
        <span class="category-name">${escapeHtml(cat.name)}</span>
        <span class="category-count">${counts[cat.id] || 0}</span>
      `;
      btn.addEventListener('click', () => selectCategory(cat.id));
      nav.appendChild(btn);
    }
    allBtn.classList.toggle('active', state.currentCategory === 'all');
  }

  function renderEntries() {
    const grid = document.getElementById('entries-grid');
    const empty = document.getElementById('empty-state');
    const entries = filteredEntries();
    document.getElementById('entry-count-label').textContent = `${entries.length} entrée${entries.length > 1 ? 's' : ''}`;

    if (!state.vault.entries.length) {
      empty.hidden = false;
      empty.querySelector('h2').textContent = 'Ton coffre est vide';
      empty.querySelector('p').textContent = 'Envoie tes captures à Claude pour ajouter tes comptes.';
      grid.innerHTML = '';
      return;
    }
    if (!entries.length) {
      empty.hidden = false;
      empty.querySelector('h2').textContent = 'Aucun résultat';
      empty.querySelector('p').textContent = 'Aucune entrée ne correspond à ta recherche.';
      grid.innerHTML = '';
      return;
    }
    empty.hidden = true;
    grid.innerHTML = '';
    for (const e of entries) {
      grid.appendChild(renderEntryCard(e));
    }
  }

  function renderEntryCard(entry) {
    const cat = getCategoryById(entry.category);
    const card = document.createElement('article');
    card.className = 'entry-card';
    if (cat?.color) card.style.setProperty('--accent', cat.color);

    const head = document.createElement('div');
    head.className = 'entry-head';
    head.innerHTML = `
      <div class="entry-icon">${entry.icon || cat?.icon || '🔑'}</div>
      <div class="entry-meta">
        <div class="entry-name">${escapeHtml(entry.name)}</div>
        <div class="entry-cat">${escapeHtml(cat?.name || entry.category)}</div>
      </div>
      <button class="entry-detail-btn" title="Détails" aria-label="Détails">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      </button>
    `;
    head.querySelector('.entry-detail-btn').addEventListener('click', () => openModal(entry));
    head.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      openModal(entry);
    });
    card.appendChild(head);

    const fields = document.createElement('div');
    fields.className = 'entry-fields';
    const previewFields = [];
    if (entry.username) previewFields.push({ label: 'Login', value: entry.username, copy: true });
    else if (entry.email) previewFields.push({ label: 'Email', value: entry.email, copy: true });
    if (entry.password) previewFields.push({ label: 'Pass', value: entry.password, copy: true, secret: true, id: entry.id + ':password' });
    if (!previewFields.length && entry.url) previewFields.push({ label: 'URL', value: entry.url, copy: true, link: true });

    for (const f of previewFields) {
      fields.appendChild(renderField(f));
    }
    card.appendChild(fields);
    return card;
  }

  function renderField(f) {
    const row = document.createElement('div');
    row.className = 'field';
    const isHidden = f.secret && !state.visiblePasswords.has(f.id);
    const displayValue = isHidden ? '•'.repeat(Math.min(12, f.value.length)) : f.value;
    row.innerHTML = `
      <span class="field-label">${f.label}</span>
      <span class="field-value ${f.link ? 'is-link' : ''} ${isHidden ? 'password-masked' : ''}">${escapeHtml(displayValue)}</span>
      <span class="field-actions"></span>
    `;
    const actions = row.querySelector('.field-actions');
    if (f.secret) {
      const eye = iconBtn(isHidden ? svgEye() : svgEyeOff(), isHidden ? 'Afficher' : 'Masquer');
      eye.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (state.visiblePasswords.has(f.id)) state.visiblePasswords.delete(f.id);
        else state.visiblePasswords.add(f.id);
        renderEntries();
      });
      actions.appendChild(eye);
    }
    if (f.copy) {
      const cp = iconBtn(svgCopy(), 'Copier');
      cp.addEventListener('click', (ev) => {
        ev.stopPropagation();
        copy(f.value, f.label);
      });
      actions.appendChild(cp);
    }
    return row;
  }

  function iconBtn(svg, title) {
    const b = document.createElement('button');
    b.className = 'field-btn';
    b.title = title;
    b.setAttribute('aria-label', title);
    b.innerHTML = svg;
    return b;
  }

  const svgCopy = () => `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
  const svgEye = () => `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  const svgEyeOff = () => `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
  const svgExt = () => `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`;

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // --------- Modal ---------
  const modal = document.getElementById('modal');
  function openModal(entry) {
    const cat = getCategoryById(entry.category);
    document.getElementById('modal-icon').textContent = entry.icon || cat?.icon || '🔑';
    document.getElementById('modal-name').textContent = entry.name;
    document.getElementById('modal-category').textContent = cat?.name || entry.category;

    const body = document.getElementById('modal-body');
    body.innerHTML = '';

    const detailFields = [
      ['Email', entry.email, true],
      ['Login / Identifiant', entry.username, true],
      ['Mot de passe', entry.password, true, true],
      ['URL', entry.url, true, false, true],
      ['Notes', entry.notes, false, false, false, true],
    ];
    for (const [label, value, copyable, secret, isLink, multiline] of detailFields) {
      if (!value) continue;
      body.appendChild(detailField(entry.id, label, value, { copyable, secret, isLink, multiline }));
    }
    if (entry.extra && Array.isArray(entry.extra)) {
      for (const f of entry.extra) {
        body.appendChild(detailField(entry.id, f.label, f.value, { copyable: true, secret: !!f.secret, multiline: !!f.multiline }));
      }
    }
    modal.hidden = false;
    resetAutoLock();
  }

  function detailField(entryId, label, value, opts) {
    const id = `${entryId}:${label}`;
    const row = document.createElement('div');
    row.className = 'detail-field';
    const isHidden = opts.secret && !state.visiblePasswords.has(id);
    const displayValue = isHidden ? '•'.repeat(Math.min(16, value.length)) : value;

    const head = document.createElement('div');
    head.className = 'detail-field-head';
    head.innerHTML = `<span class="detail-field-label">${escapeHtml(label)}</span>`;
    const actions = document.createElement('div');
    actions.className = 'detail-field-actions';
    if (opts.secret) {
      const eye = iconBtn(isHidden ? svgEye() : svgEyeOff(), isHidden ? 'Afficher' : 'Masquer');
      eye.addEventListener('click', () => {
        if (state.visiblePasswords.has(id)) state.visiblePasswords.delete(id);
        else state.visiblePasswords.add(id);
        openModal(state.vault.entries.find(e => e.id === entryId));
      });
      actions.appendChild(eye);
    }
    if (opts.isLink && value) {
      const ext = iconBtn(svgExt(), 'Ouvrir');
      ext.addEventListener('click', () => {
        const url = value.startsWith('http') ? value : 'https://' + value;
        window.open(url, '_blank', 'noopener,noreferrer');
      });
      actions.appendChild(ext);
    }
    if (opts.copyable) {
      const cp = iconBtn(svgCopy(), 'Copier');
      cp.addEventListener('click', () => copy(value, label));
      actions.appendChild(cp);
    }
    head.appendChild(actions);
    row.appendChild(head);

    const v = document.createElement('div');
    v.className = 'detail-field-value' + (opts.isLink ? ' is-link' : '');
    if (opts.isLink && !isHidden) {
      const url = value.startsWith('http') ? value : 'https://' + value;
      v.innerHTML = `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(value)}</a>`;
    } else {
      v.textContent = displayValue;
    }
    row.appendChild(v);
    return row;
  }

  function closeModal() { modal.hidden = true; }
  modal.addEventListener('click', (e) => {
    if (e.target.closest('[data-close-modal]')) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modal.hidden) closeModal();
    if ((e.metaKey || e.ctrlKey) && e.key === 'k' && state.vault) {
      e.preventDefault();
      document.getElementById('search').focus();
    }
    if (state.vault) resetAutoLock();
  });

  // --------- Category selection ---------
  function selectCategory(id) {
    state.currentCategory = id;
    document.querySelectorAll('.category-item').forEach(b => b.classList.toggle('active', b.dataset.category === id));
    renderEntries();
    document.querySelector('.sidebar')?.classList.remove('open');
  }
  document.querySelector('[data-category="all"]').addEventListener('click', () => selectCategory('all'));

  // --------- Search ---------
  const searchInput = document.getElementById('search');
  searchInput.addEventListener('input', () => {
    state.search = searchInput.value;
    renderEntries();
  });

  // --------- Sidebar toggle (mobile) ---------
  document.getElementById('sidebar-open').addEventListener('click', () => {
    document.querySelector('.sidebar').classList.add('open');
  });
  document.getElementById('sidebar-close').addEventListener('click', () => {
    document.querySelector('.sidebar').classList.remove('open');
  });

  // --------- Lock button ---------
  document.getElementById('lock-btn').addEventListener('click', lock);

  // --------- Password visibility toggles (lock screen) ---------
  document.querySelectorAll('.toggle-visibility').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.target);
      target.type = target.type === 'password' ? 'text' : 'password';
    });
  });

  // --------- Full render ---------
  function renderAll() {
    renderCategories();
    renderEntries();
  }

  // Activity tracking for auto-lock
  ['mousedown', 'keydown', 'touchstart'].forEach(evt => {
    document.addEventListener(evt, () => { if (state.vault) resetAutoLock(); }, { passive: true });
  });
})();
