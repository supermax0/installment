/* auth.js - تسجيل دخول + مزامنة المستخدمين (Firestore) */
(function () {
  'use strict';

  const AUTH_KEYS = {
    users: 'installments_auth_users',
    usersUpdatedAt: 'installments_auth_users_updatedAt',
    session: 'installments_auth_session'
  };

  function safeJsonParse(str, fallback) {
    try {
      return JSON.parse(str);
    } catch (_) {
      return fallback;
    }
  }

  function normalizeUsername(u) {
    return (u || '').toString().trim().toLowerCase();
  }

  function getUsersUpdatedAt() {
    const v = Number(localStorage.getItem(AUTH_KEYS.usersUpdatedAt) || 0);
    return Number.isFinite(v) ? v : 0;
  }

  function setUsersUpdatedAt(ts) {
    localStorage.setItem(AUTH_KEYS.usersUpdatedAt, String(Number(ts) || Date.now()));
  }

  function getUsersRaw() {
    const raw = localStorage.getItem(AUTH_KEYS.users);
    const users = safeJsonParse(raw, []);
    return Array.isArray(users) ? users : [];
  }

  function sanitizeUsers(list) {
    if (!Array.isArray(list)) return [];
    const out = [];
    const seen = new Set();
    list.forEach(u => {
      if (!u || typeof u !== 'object') return;
      const username = (u.username || '').toString().trim();
      const nu = normalizeUsername(username);
      if (!username || !nu) return;
      if (seen.has(nu)) return;
      seen.add(nu);

      // legacy: {username, password}
      if (typeof u.password === 'string' && u.password) {
        out.push({
          username,
          password: u.password,
          createdAt: Number(u.createdAt || 0) || 0,
          updatedAt: Number(u.updatedAt || 0) || 0
        });
        return;
      }

      // new: {username, passwordHash, salt}
      const passwordHash = (u.passwordHash || '').toString();
      const salt = (u.salt || '').toString();
      if (!passwordHash || !salt) return;
      out.push({
        username,
        passwordHash,
        salt,
        createdAt: Number(u.createdAt || 0) || 0,
        updatedAt: Number(u.updatedAt || 0) || 0
      });
    });
    return out;
  }

  function getUsers() {
    return sanitizeUsers(getUsersRaw());
  }

  function setUsers(users, { touch = true } = {}) {
    localStorage.setItem(AUTH_KEYS.users, JSON.stringify(sanitizeUsers(users)));
    if (touch) setUsersUpdatedAt(Date.now());
  }

  function ensureDefaultUser() {
    // للإبقاء على التوافق مع app.js / login.js فقط
    return false;
  }

  function hasUsers() {
    return getUsers().length > 0;
  }

  function canUseCloud() {
    return !!(window.firebaseDB &&
      typeof window.firebaseDB.init === 'function' &&
      typeof window.firebaseDB.ready === 'function' &&
      typeof window.firebaseDB.getAuthUsersFirestore === 'function' &&
      typeof window.firebaseDB.setAuthUsersFirestore === 'function');
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function randomSaltHex(lenBytes = 16) {
    const a = new Uint8Array(lenBytes);
    (crypto || window.crypto).getRandomValues(a);
    return bytesToHex(a);
  }

  async function sha256Hex(str) {
    const enc = new TextEncoder();
    const data = enc.encode(str);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return bytesToHex(new Uint8Array(hash));
  }

  async function hashPassword(password, salt) {
    return sha256Hex(`${salt}|${password}`);
  }

  async function migrateLegacyUsersToHashed() {
    const users = getUsers();
    let changed = false;
    const now = Date.now();
    for (let i = 0; i < users.length; i++) {
      const u = users[i];
      if (u && typeof u.password === 'string' && u.password) {
        const salt = randomSaltHex(16);
        const passwordHash = await hashPassword(u.password, salt);
        users[i] = {
          username: u.username,
          salt,
          passwordHash,
          createdAt: u.createdAt || now,
          updatedAt: now
        };
        changed = true;
      }
    }
    if (changed) setUsers(users, { touch: true });
    return changed;
  }

  function mergeUsers(localUsers, remoteUsers) {
    const map = new Map();
    const pushUser = (u) => {
      if (!u || !u.username) return;
      const key = normalizeUsername(u.username);
      if (!key) return;
      const prev = map.get(key);
      const prevTs = Number(prev?.updatedAt || 0) || 0;
      const curTs = Number(u.updatedAt || 0) || 0;
      if (!prev || curTs >= prevTs) map.set(key, u);
    };
    (localUsers || []).forEach(pushUser);
    (remoteUsers || []).forEach(pushUser);
    return Array.from(map.values());
  }

  async function cloudPullUsers() {
    if (!canUseCloud()) return null;
    try {
      window.firebaseDB.init();
      if (!window.firebaseDB.ready()) return null;
      return await window.firebaseDB.getAuthUsersFirestore();
    } catch (_) {
      return null;
    }
  }

  async function cloudPushUsers(doc) {
    if (!canUseCloud()) return false;
    try {
      window.firebaseDB.init();
      if (!window.firebaseDB.ready()) return false;
      return await window.firebaseDB.setAuthUsersFirestore(doc);
    } catch (_) {
      return false;
    }
  }

  let readyPromise = null;
  let syncPromise = null;

  async function syncUsersNow() {
    if (syncPromise) return syncPromise;
    syncPromise = (async () => {
      // تهيئة Firebase إن كانت موجودة
      if (window.firebaseDB && typeof window.firebaseDB.init === 'function') {
        try { window.firebaseDB.init(); } catch (_) {}
      }

      // ترقية أي بيانات قديمة إلى hash
      await migrateLegacyUsersToHashed();

      // مزامنة من/إلى السحابة (إن أمكن)
      const remote = await cloudPullUsers();
      const remoteUsers = sanitizeUsers(remote?.users || []);
      const remoteUpdatedAt = Number(remote?.updatedAt || 0) || 0;

      const localUsers = getUsers();
      const localUpdatedAt = getUsersUpdatedAt();

      const merged = mergeUsers(localUsers, remoteUsers);
      const mergedUpdatedAt = Math.max(remoteUpdatedAt, localUpdatedAt, Date.now());

      setUsers(merged, { touch: false });
      setUsersUpdatedAt(mergedUpdatedAt);

      const remoteJson = JSON.stringify({ users: remoteUsers, updatedAt: remoteUpdatedAt });
      const mergedJson = JSON.stringify({ users: merged, updatedAt: mergedUpdatedAt });

      if (remoteJson !== mergedJson) {
        await cloudPushUsers({ schema: 1, updatedAt: mergedUpdatedAt, users: merged });
      }
      return true;
    })();
    try {
      return await syncPromise;
    } finally {
      syncPromise = null;
    }
  }

  async function ready() {
    if (readyPromise) return readyPromise;
    readyPromise = syncUsersNow();
    return readyPromise;
  }

  async function createFirstUser({ username, password, confirmPassword } = {}) {
    await ready();
    const uRaw = (username || '').toString();
    const u = uRaw.trim();
    const p = (password || '').toString();
    const c = (confirmPassword || '').toString();

    if (hasUsers()) return { ok: false, error: 'تم إعداد تسجيل الدخول مسبقاً.' };
    if (!u || !p) return { ok: false, error: 'يرجى إدخال اسم المستخدم وكلمة المرور.' };
    if (p.length < 4) return { ok: false, error: 'كلمة المرور قصيرة جداً (على الأقل 4 أحرف).' };
    if (p !== c) return { ok: false, error: 'تأكيد كلمة المرور غير مطابق.' };
    if (u.length > 32) return { ok: false, error: 'اسم المستخدم طويل جداً.' };

    const now = Date.now();
    const salt = randomSaltHex(16);
    const passwordHash = await hashPassword(p, salt);
    setUsers([{ username: u, salt, passwordHash, createdAt: now, updatedAt: now }], { touch: true });
    await syncUsersNow(); // دفع للسحابة (إذا متاح)
    return { ok: true, username: u };
  }

  function getSession() {
    const raw = localStorage.getItem(AUTH_KEYS.session);
    const session = safeJsonParse(raw, null);
    if (!session || typeof session !== 'object') return null;
    if (!session.username || !session.expiresAt) return null;

    const expiresAt = Number(session.expiresAt);
    if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) {
      localStorage.removeItem(AUTH_KEYS.session);
      return null;
    }
    return session;
  }

  function isLoggedIn() {
    return !!getSession();
  }

  async function login({ username, password, remember } = {}) {
    await ready();
    const u = normalizeUsername(username);
    const p = (password || '').toString();
    if (!u || !p) return { ok: false, error: 'يرجى إدخال اسم المستخدم وكلمة المرور.' };

    const users = getUsers();
    const idx = users.findIndex(x => normalizeUsername(x.username) === u);
    if (idx === -1) return { ok: false, error: 'بيانات الدخول غير صحيحة.' };

    const found = users[idx];
    // legacy fallback (إذا وصلتنا بيانات قديمة)
    if (typeof found.password === 'string' && found.password) {
      if (found.password !== p) return { ok: false, error: 'بيانات الدخول غير صحيحة.' };
      // migrate this user
      const now = Date.now();
      const salt = randomSaltHex(16);
      const passwordHash = await hashPassword(p, salt);
      users[idx] = {
        username: found.username,
        salt,
        passwordHash,
        createdAt: found.createdAt || now,
        updatedAt: now
      };
      setUsers(users, { touch: true });
      await syncUsersNow();
    } else {
      const check = await hashPassword(p, found.salt);
      if (check !== found.passwordHash) return { ok: false, error: 'بيانات الدخول غير صحيحة.' };
    }

    const ttlMs = remember ? (30 * 24 * 60 * 60 * 1000) : (12 * 60 * 60 * 1000);
    const session = {
      username: found.username,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttlMs
    };
    localStorage.setItem(AUTH_KEYS.session, JSON.stringify(session));
    return { ok: true, username: found.username };
  }

  function logout() {
    localStorage.removeItem(AUTH_KEYS.session);
  }

  async function changePassword({ username, oldPassword, newPassword } = {}) {
    await ready();
    const u = normalizeUsername(username);
    const oldP = (oldPassword || '').toString();
    const newP = (newPassword || '').toString();

    if (!u || !oldP || !newP) return { ok: false, error: 'يرجى تعبئة جميع الحقول.' };
    if (newP.length < 4) return { ok: false, error: 'كلمة المرور الجديدة قصيرة جداً (على الأقل 4 أحرف).' };

    const users = getUsers();
    const idx = users.findIndex(x => normalizeUsername(x.username) === u);
    if (idx === -1) return { ok: false, error: 'المستخدم غير موجود.' };

    const user = users[idx];
    if (typeof user.password === 'string' && user.password) {
      if (user.password !== oldP) return { ok: false, error: 'كلمة المرور الحالية غير صحيحة.' };
    } else {
      const check = await hashPassword(oldP, user.salt);
      if (check !== user.passwordHash) return { ok: false, error: 'كلمة المرور الحالية غير صحيحة.' };
    }

    const now = Date.now();
    const salt = randomSaltHex(16);
    const passwordHash = await hashPassword(newP, salt);
    users[idx] = {
      username: user.username,
      salt,
      passwordHash,
      createdAt: user.createdAt || now,
      updatedAt: now
    };
    setUsers(users, { touch: true });
    await syncUsersNow();
    return { ok: true };
  }

  function getNextFromQuery() {
    try {
      const params = new URLSearchParams(window.location.search || '');
      const next = params.get('next') || '';
      if (!next) return 'index.html';
      const lowered = next.toLowerCase();
      if (lowered.includes('://') || lowered.startsWith('javascript:')) return 'index.html';
      return next;
    } catch (_) {
      return 'index.html';
    }
  }

  function redirectToLogin(next = 'index.html') {
    const url = `login.html?next=${encodeURIComponent(next)}`;
    window.location.replace(url);
  }

  window.auth = {
    AUTH_KEYS,
    getUsers,
    ensureDefaultUser,
    hasUsers,
    createFirstUser,
    getSession,
    isLoggedIn,
    ready,
    syncUsersNow,
    login,
    logout,
    changePassword,
    getNextFromQuery,
    redirectToLogin
  };
})();

