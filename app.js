/* ============================================================
   抖音视频笔记 · 检索站  主逻辑
   - 精准搜索：整句/多关键词完整连续匹配
   - 模糊搜索：bigram 倒排索引 + 覆盖率打分，容忍错字与语序
   - 补充内容：IndexedDB 持久化，并入搜索
   - 日间/夜间：CSS 变量 + localStorage
   ============================================================ */
'use strict';

/* ---------------- 基础工具 ---------------- */
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

let toastTimer = null;
function toast(msg) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2000);
}

/** 归一化：只保留中文、字母、数字，转小写 */
function norm(s) {
  return String(s).toLowerCase().replace(/[^\u4e00-\u9fa5a-z0-9]+/g, '');
}

/** 生成 bigram（相邻两字）。单字查询退化为自身 */
function grams(s) {
  const n = norm(s);
  const out = [];
  if (!n) return out;
  if (n.length === 1) { out.push(n); return out; }
  for (let i = 0; i < n.length - 1; i++) out.push(n.slice(i, i + 2));
  return out;
}

function uniq(arr) {
  return Array.from(new Set(arr));
}

/* ---------------- 本地存储 ---------------- */
const LS = {
  get(k, d) {
    try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); }
    catch (e) { return d; }
  },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* 隐私模式忽略 */ } },
};

/* ---------------- IndexedDB：补充内容 ---------------- */
const DB = {
  db: null,
  open() {
    return new Promise((resolve) => {
      if (DB.db) return resolve(DB.db);
      let req;
      try { req = indexedDB.open('notes-extra', 2); }
      catch (e) { return resolve(null); }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('extras')) {
          db.createObjectStore('extras', { keyPath: 'id' });
        }
        // v2：存放不可导出的 CryptoKey（记住解锁状态用）
        if (!db.objectStoreNames.contains('keys')) {
          db.createObjectStore('keys');
        }
      };
      req.onsuccess = () => { DB.db = req.result; resolve(DB.db); };
      req.onerror = () => resolve(null);
    });
  },
  async all() {
    const db = await DB.open();
    if (!db) return [];
    return new Promise((resolve) => {
      const tx = db.transaction('extras', 'readonly');
      const rq = tx.objectStore('extras').getAll();
      rq.onsuccess = () => resolve(rq.result || []);
      rq.onerror = () => resolve([]);
    });
  },
  async put(item) {
    const db = await DB.open();
    if (!db) return false;
    return new Promise((resolve) => {
      const tx = db.transaction('extras', 'readwrite');
      tx.objectStore('extras').put(item);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => resolve(false);
    });
  },
  async del(id) {
    const db = await DB.open();
    if (!db) return false;
    return new Promise((resolve) => {
      const tx = db.transaction('extras', 'readwrite');
      tx.objectStore('extras')['delete'](id);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => resolve(false);
    });
  },
  /* --- 解锁密钥：存的是不可导出的 CryptoKey 对象，取不出原始字节 --- */
  async getKey(name) {
    const db = await DB.open();
    if (!db || !db.objectStoreNames.contains('keys')) return null;
    return new Promise((resolve) => {
      let rq;
      try { rq = db.transaction('keys', 'readonly').objectStore('keys').get(name); }
      catch (e) { return resolve(null); }
      rq.onsuccess = () => resolve(rq.result || null);
      rq.onerror = () => resolve(null);
    });
  },
  async setKey(name, val) {
    const db = await DB.open();
    if (!db || !db.objectStoreNames.contains('keys')) return false;
    return new Promise((resolve) => {
      let tx;
      try { tx = db.transaction('keys', 'readwrite'); }
      catch (e) { return resolve(false); }
      tx.objectStore('keys').put(val, name);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => resolve(false);
    });
  },
  async delKey(name) {
    const db = await DB.open();
    if (!db || !db.objectStoreNames.contains('keys')) return false;
    return new Promise((resolve) => {
      let tx;
      try { tx = db.transaction('keys', 'readwrite'); }
      catch (e) { return resolve(false); }
      tx.objectStore('keys')['delete'](name);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => resolve(false);
    });
  },
};

/* ---------------- 加密 / 解密 ---------------- */
/* 密文容器：NB01 | salt(16B) | iv(12B) | ciphertext | GCM tag(16B) */
const CRYPTO_CFG = { iterations: 600000, keyLen: 256, hash: 'SHA-256' };
const MAGIC = [0x4e, 0x42, 0x30, 0x31]; // 'NB01'

function u8(buf) { return new Uint8Array(buf); }

async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: CRYPTO_CFG.iterations, hash: CRYPTO_CFG.hash },
    km,
    { name: 'AES-GCM', length: CRYPTO_CFG.keyLen },
    false, // 不可导出，可安全存入 IndexedDB
    ['encrypt', 'decrypt']
  );
}

/** 解析密文容器，取出 salt / iv / 密文+tag */
function parseContainer(bytes) {
  if (bytes.length < 4 + 16 + 12 + 16) throw new Error('文件损坏');
  for (let i = 0; i < 4; i += 1) {
    if (bytes[i] !== MAGIC[i]) throw new Error('文件格式不对');
  }
  return {
    salt: bytes.slice(4, 20),
    iv: bytes.slice(20, 32),
    body: bytes.slice(32),
  };
}

/** 用密钥解出明文字节并转成 JSON 对象 */
async function decryptJSON(bytes, key) {
  const { iv, body } = parseContainer(bytes);
  // GCM 认证标签固定在末尾 16 字节，校验失败即代表口令错误
  const cipherText = body.slice(0, body.length - 16);
  const tag = body.slice(body.length - 16);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    (() => { const b = new Uint8Array(cipherText.length + tag.length); b.set(cipherText, 0); b.set(tag, cipherText.length); return b; })()
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

/* ---------------- 全局状态 ---------------- */
const S = {
  lite: null,        // 轻量目录
  docs: [],          // 全部可检索文档 {id,chapter,no,title,meta,summary,seq,gseq,fullText,src}
  bi: new Map(),     // bigram -> [docIdx]
  titleBi: new Map(),// 标题 bigram -> [docIdx]
  ready: false,
  mode: 'exact',
  query: '',
  results: [],
  readerIdx: -1,
  history: LS.get('nb_hist', []),
  extras: [],
  pendingHit: 0,
};

/* ---------------- 主题 ---------------- */
const THEME_KEY = 'nb_theme';

function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  $('#themeIcon').textContent = t === 'dark' ? '☀' : '☾';
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', t === 'dark' ? '#15171c' : '#f6f4ef');
}

function initTheme() {
  const saved = LS.get(THEME_KEY, null);
  if (saved === 'dark' || saved === 'light') return applyTheme(saved);
  const dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(dark ? 'dark' : 'light');
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  LS.set(THEME_KEY, next);
  toast(next === 'dark' ? '已切换到夜间模式' : '已切换到日间模式');
}

/* ---------------- 字号 ---------------- */
const FONT_KEY = 'nb_font';
function applyFont(px) {
  document.documentElement.style.setProperty('--reader-font', px + 'px');
  LS.set(FONT_KEY, px);
}
function initFont() { applyFont(LS.get(FONT_KEY, 17)); }

/* ---------------- 数据加载（密文） ---------------- */
const REMEMBER_DAYS = 30;

const LOCK = {
  key: null,       // 当前会话的 CryptoKey（不可导出）
  encIndex: null,  // index.enc 字节
  encFull: null,   // full.enc 字节
  busy: false,
};

/* 内容版本号：每次更换根目录的 .enc 后，把下面这行的值改一下（比如 v2、v3），
   所有访客就会立刻拉到新文件，不会被浏览器缓存 / CDN 缓存 / Service Worker 挡住。 */
const DATA_VER = 'v3';

async function fetchBytes(url) {
  const sep = url.indexOf('?') === -1 ? '?' : '&';
  // 带版本号查询串 => 新 URL => 缓存里必然没有，直接取新文件
  const r = await fetch(url + sep + 'v=' + DATA_VER, { cache: 'no-cache' });
  if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + url);
  const buf = await r.arrayBuffer();
  if (buf.byteLength < 32) {
    // QQ 浏览器等会把二进制文件转码成文本，导致字节被截断
    throw new Error('文件截断：' + buf.byteLength + ' 字节（应为 >32），浏览器可能拦截了二进制下载。请换 Chrome/Safari 或关闭省流量模式。');
  }
  return u8(buf);
}

/** 拉取密文：index 先到（含 salt），full 后台并行下载不阻塞解锁界面 */
async function fetchCipher() {
  const pFull = fetchBytes('full.enc')
    .then((b) => { LOCK.encFull = b; })
    .catch(() => { LOCK.encFull = null; });
  LOCK.encIndex = await fetchBytes('index.enc');
  return pFull;
}

/** 输入口令 → 派生密钥 → 试解目录（GCM 校验失败即口令错误） */
async function unlockWith(password) {
  const { salt } = parseContainer(LOCK.encIndex);
  const key = await deriveKey(password, salt);
  const lite = await decryptJSON(LOCK.encIndex, key);
  LOCK.key = key;
  return lite;
}

async function loadData() {
  const statusEl = $('#status');
  try {
    await fetchCipher();
  } catch (e) {
    showLock('密文加载失败，请检查网络后重试。');
    return;
  }

  // 这台设备之前记住过密钥，直接静默解锁
  const saved = await DB.getKey('main');
  if (saved) {
    try {
      const exp = await DB.getKey('mainExp');
      if (exp && Date.now() > exp) throw new Error('expired');
      S.lite = await decryptJSON(LOCK.encIndex, saved);
      LOCK.key = saved;
      markRemembered();
      afterUnlock();
      return;
    } catch (e) {
      await DB.delKey('main');
      await DB.delKey('mainExp');
    }
  }
  showLock('');
}

/** 解锁成功后的原有加载流程，与加密前完全一致 */
async function afterUnlock() {
  const statusEl = $('#status');
  renderStats();
  renderToc();
  statusEl.textContent = '正在准备全文检索…';

  // 首屏让出主线程，再解密全文
  setTimeout(async () => {
    try {
      let full;
      if (LOCK.encFull) {
        full = await decryptJSON(LOCK.encFull, LOCK.key);
      } else {
        // 首次进入时全文可能还在下载，补拉一次
        LOCK.encFull = await fetchBytes('full.enc');
        full = await decryptJSON(LOCK.encFull, LOCK.key);
      }
      buildDocs(full);
      await loadExtras();
      await buildIndex();
      S.ready = true;
      statusEl.textContent = '';
      if (S.query) doSearch();
      else showHome();
    } catch (e) {
      // AES-GCM 校验失败时浏览器给出的 message 为空，补一句人话
      statusEl.textContent = '全文解密失败：' + (e.message || '密钥与数据不匹配，请用同一次加密生成的 .enc 文件')
        + '（若是刚换过 .enc，请在网址后加 ?reset=1 打开一次，强制清空本机缓存）';
    }
  }, 30);
}

/* ---------------- 解锁界面 ---------------- */
function markRemembered() {
  const btn = $('#btnLock');
  if (btn) btn.hidden = false;
}

function showLock(errMsg) {
  const mask = $('#lockMask');
  if (!mask) return;
  mask.hidden = false;
  mask.classList.add('isOn');
  const err = $('#lockErr');
  if (err) err.textContent = errMsg || '';
  const input = $('#lockPwd');
  if (input) setTimeout(() => input.focus(), 60);
}

function hideLock() {
  const mask = $('#lockMask');
  if (!mask) return;
  mask.classList.remove('isOn');
  mask.hidden = true;
}

async function submitLock(e) {
  if (e) e.preventDefault();
  if (LOCK.busy) return;
  const input = $('#lockPwd');
  const err = $('#lockErr');
  const btn = $('#lockBtn');
  const pwd = (input.value || '').trim();
  if (!pwd) {
    err.textContent = '请输入访问口令';
    return;
  }
  LOCK.busy = true;
  btn.disabled = true;
  const oldLabel = btn.textContent;
  btn.textContent = '正在解锁…';
  err.textContent = '';
  try {
    S.lite = await unlockWith(pwd);
    // 勾了「记住」就把不可导出的密钥存进 IndexedDB，30 天有效
    if ($('#lockRemember') && $('#lockRemember').checked) {
      await DB.setKey('main', LOCK.key);
      await DB.setKey('mainExp', Date.now() + REMEMBER_DAYS * 86400000);
      markRemembered();
    }
    input.value = '';
    hideLock();
    afterUnlock();
  } catch (err2) {
    err.textContent = '口令不对，请重试';
    input.select();
  } finally {
    LOCK.busy = false;
    btn.disabled = false;
    btn.textContent = oldLabel;
  }
}

/** 立即锁定：丢弃本机保存的密钥并回到解锁界面 */
async function lockNow() {
  await DB.delKey('main');
  await DB.delKey('mainExp');
  LOCK.key = null;
  S.ready = false;
  S.docs = [];
  S.bi = new Map();
  S.titleBi = new Map();
  S.results = [];
  const btn = $('#btnLock');
  if (btn) btn.hidden = true;
  $('#results').innerHTML = '';
  $('#tocList').innerHTML = '';
  $('#status').textContent = '已锁定';
  showLock('');
  toast('已锁定，需重新输入口令');
}

/** 把 full.json 展开为扁平文档数组，并生成检索用全文 */
function buildDocs(full) {
  const docs = [];
  (full.chapters || []).forEach((ch) => {
    (ch.items || []).forEach((it) => {
      const parts = [it.no, it.title, it.meta];
      const sections = (it.sections || []).map((s) => ({
        h: s.h || '',
        // 表格的列宽 w 必须一起带上，否则渲染时拿不到 Word 里调好的比例
        b: (s.b || []).map((b) => (Array.isArray(b.w) ? { t: b.t, v: b.v, w: b.w } : { t: b.t, v: b.v })),
      }));
      sections.forEach((s) => {
        if (s.h) parts.push(s.h);
        s.b.forEach((b) => {
          if (b.t === 'p') parts.push(b.v);
          else if (b.t === 'table') (b.v || []).forEach((row) => parts.push((row || []).join(' ')));
        });
      });
      docs.push({
        id: it.id, chapter: ch.chapter, no: it.no || '', title: it.title || '',
        meta: it.meta || '', seq: it.seq, gseq: it.gseq,
        sections, src: 'doc',
        fullText: parts.filter(Boolean).join('\n'),
      });
    });
  });
  S.docs = docs;
}

/* ---------------- 倒排索引 ---------------- */
async function buildIndex() {
  S.bi = new Map();
  S.titleBi = new Map();
  const t0 = performance.now();
  for (let i = 0; i < S.docs.length; i++) {
    addDocToIndex(i);
    // 每 15 篇让出一次主线程，避免长时间卡住界面
    if (i % 15 === 14) await new Promise((r) => setTimeout(r, 0));
  }
  console.log('索引构建完成', S.docs.length, '篇', Math.round(performance.now() - t0), 'ms');
}

function addDocToIndex(idx) {
  const d = S.docs[idx];
  pushGrams(S.bi, d.fullText, idx);
  pushGrams(S.titleBi, d.title + ' ' + d.no, idx, true);
}

function pushGrams(map, text, idx, skipDup) {
  const gs = grams(text);
  const seen = skipDup ? new Set() : null;
  for (let i = 0; i < gs.length; i++) {
    const g = gs[i];
    if (seen) {
      if (seen.has(g)) continue;
      seen.add(g);
    } else {
      // 正文不去重，用「最后写入」避免同文档重复 push
      const arr = map.get(g);
      if (arr && arr[arr.length - 1] === idx) continue;
    }
    let arr = map.get(g);
    if (!arr) { arr = []; map.set(g, arr); }
    arr.push(idx);
  }
}

/* ---------------- 搜索 ---------------- */
/** 把查询拆成搜索词：空格分隔的多个词，全部须出现（AND） */
function splitTerms(q) {
  return q.trim().split(/[\s,，、;；]+/).filter((t) => t.length > 0);
}

/** 高亮词表 */
function hlTerms(q, mode) {
  const terms = splitTerms(q).filter((t) => t.length >= 2);
  if (mode === 'fuzzy') {
    // 模糊模式下额外尝试两字片段，提升可读性
    const extra = [];
    terms.forEach((t) => {
      if (t.length >= 4) {
        for (let i = 0; i + 2 <= t.length; i += 2) extra.push(t.slice(i, i + 2));
      }
    });
    return uniq(terms.concat(extra)).slice(0, 8);
  }
  return terms;
}

function searchExact(q) {
  const terms = splitTerms(q);
  if (!terms.length) return [];
  const lower = terms.map((t) => t.toLowerCase());
  const out = [];
  for (let i = 0; i < S.docs.length; i++) {
    const d = S.docs[i];
    const text = d.fullText.toLowerCase();
    let total = 0;
    let firstPos = -1;
    let ok = true;
    for (let k = 0; k < lower.length; k++) {
      let pos = text.indexOf(lower[k]);
      if (pos === -1) { ok = false; break; }
      let cnt = 0, p = pos;
      while (p !== -1) { cnt++; p = text.indexOf(lower[k], p + lower[k].length); }
      total += cnt;
      if (firstPos === -1 || pos < firstPos) firstPos = pos;
    }
    if (!ok) continue;
    const tl = d.title.toLowerCase();
    let titleScore = 0;
    lower.forEach((w) => {
      if (tl === w) titleScore += 200;        // 标题正好等于该词
      else if (tl.indexOf(w) !== -1) titleScore += 80;  // 标题包含该词
    });
    const noHit = d.no && d.no.toLowerCase().indexOf(lower[0]) !== -1 ? 20 : 0;
    out.push({
      i,
      score: total * 10 + titleScore + noHit + (firstPos < 200 ? 15 : 0),
      firstPos,
    });
  }
  out.sort((a, b) => b.score - a.score || a.firstPos - b.firstPos);
  return out;
}

function searchFuzzy(q) {
  const qg = grams(q);
  if (!qg.length) return [];
  const uniqG = uniq(qg);
  const hits = new Map();      // docIdx -> 命中 gram 数
  const titleHits = new Map();

  uniqG.forEach((g) => {
    const arr = S.bi.get(g);
    if (arr) {
      let last = -1;
      for (let k = 0; k < arr.length; k++) {
        const idx = arr[k];
        if (idx === last) continue;  // 同文档重复计数只算一次
        last = idx;
        hits.set(idx, (hits.get(idx) || 0) + 1);
      }
    }
    const tarr = S.titleBi.get(g);
    if (tarr) {
      for (let k = 0; k < tarr.length; k++) titleHits.set(tarr[k], (titleHits.get(tarr[k]) || 0) + 1);
    }
  });

  const total = uniqG.length;
  const out = [];
  hits.forEach((cnt, idx) => {
    const cov = cnt / total;
    if (cov < 0.42) return;                       // 覆盖率阈值：过滤弱相关
    const th = titleHits.get(idx) || 0;
    const titleCov = th / total;
    // 标题命中权重更高；命中数本身也参与排序
    const score = cov * 100 + titleCov * 80 + Math.min(cnt, 20) * 0.5;
    out.push({ i: idx, score, firstPos: -1 });
  });
  out.sort((a, b) => b.score - a.score);
  return out;
}

/** 提取命中片段 */
function snippet(d, q, mode) {
  const terms = splitTerms(q);
  const lower = d.fullText.toLowerCase();
  let pos = -1;
  for (let k = 0; k < terms.length; k++) {
    const p = lower.indexOf(terms[k].toLowerCase());
    if (p !== -1 && (pos === -1 || p < pos)) pos = p;
  }
  if (pos === -1) {
    if (mode === 'fuzzy') {
      // 模糊命中但无完整字面匹配：退回显示摘要
      const s = d.fullText.slice(0, 90);
      return esc(s) + '…';
    }
    return esc(d.fullText.slice(0, 90)) + '…';
  }
  const start = Math.max(0, pos - 36);
  const end = Math.min(d.fullText.length, pos + 96);
  let text = d.fullText.slice(start, end);
  if (start > 0) text = '…' + text;
  if (end < d.fullText.length) text = text + '…';
  return hlHtml(text, hlTerms(q, mode));
}

/** 计算首个匹配位置（用于阅读页定位） */
function firstHitPos(d, q) {
  const terms = splitTerms(q);
  const lower = d.fullText.toLowerCase();
  let pos = -1;
  terms.forEach((t) => {
    const p = lower.indexOf(t.toLowerCase());
    if (p !== -1 && (pos === -1 || p < pos)) pos = p;
  });
  return pos;
}

function findRanges(text, terms) {
  const lower = text.toLowerCase();
  const ranges = [];
  terms.forEach((t) => {
    if (!t) return;
    const tl = t.toLowerCase();
    let i = lower.indexOf(tl);
    let guard = 0;
    while (i !== -1 && guard++ < 200) {
      ranges.push([i, i + t.length]);
      i = lower.indexOf(tl, i + t.length);
    }
  });
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (let k = 0; k < ranges.length; k++) {
    const r = ranges[k];
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return merged;
}

function hlHtml(text, terms) {
  const rs = findRanges(text, terms);
  if (!rs.length) return esc(text);
  let out = '', pos = 0;
  for (let k = 0; k < rs.length; k++) {
    const s = rs[k][0], e = rs[k][1];
    if (s >= pos) {
      out += esc(text.slice(pos, s)) + '<mark>' + esc(text.slice(s, e)) + '</mark>';
      pos = e;
    }
  }
  return out + esc(text.slice(pos));
}

/* ---------------- 渲染 ---------------- */
function renderStats() {
  const st = (S.lite && S.lite.stats) || { items: 0, chars: 0 };
  $('#statItems').textContent = st.items || '—';
  $('#statChars').textContent = (st.chars / 10000).toFixed(1) + '万';
  $('#statExtra').textContent = S.extras.length;
  const b = $('#brand');
  if (b && S.lite) b.textContent = S.lite.title || '视频笔记';
}

function showHome() {
  $('#homeBox').hidden = !S.ready;
  $('#results').innerHTML = '';
  renderHist();
  if (S.ready) $('#status').textContent = '';
}

function renderHist() {
  const box = $('#histBox');
  const list = $('#histList');
  if (!S.history.length) { box.hidden = true; return; }
  box.hidden = false;
  list.innerHTML = '';
  S.history.slice(0, 10).forEach((h) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'chip';
    b.textContent = h;
    b.addEventListener('click', () => {
      $('#q').value = h;
      onInput();
    });
    list.appendChild(b);
  });
}

function pushHist(q) {
  S.history = [q].concat(S.history.filter((h) => h !== q)).slice(0, 10);
  LS.set('nb_hist', S.history);
  renderHist();
}

const HOT = ['命运', '风水', '定数', '王阳明', '三元九运', '心理暗示', '业障', '知行合一', '专注力', '情绪'];
function renderHot() {
  const box = $('#hotList');
  box.innerHTML = '';
  HOT.forEach((w) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'chip';
    b.textContent = w;
    b.addEventListener('click', () => { $('#q').value = w; onInput(); $('#q').focus(); });
    box.appendChild(b);
  });
}

function doSearch() {
  const q = S.query.trim();
  if (!S.ready) { $('#status').textContent = '全文检索尚未就绪，请稍候…'; return; }
  if (!q) { showHome(); return; }

  const t0 = performance.now();
  const hits = S.mode === 'exact' ? searchExact(q) : searchFuzzy(q);
  const ms = Math.round(performance.now() - t0);

  S.results = hits;
  $('#homeBox').hidden = true;
  $('#histBox').hidden = true;

  const statusEl = $('#status');
  statusEl.textContent = hits.length
    ? '找到 ' + hits.length + ' 条结果 · 用时 ' + ms + ' ms'
    : '没有找到相关内容，试试模糊搜索或换个说法。';

  const box = $('#results');
  box.innerHTML = '';
  const terms = hlTerms(q, S.mode);
  const limit = Math.min(hits.length, 80);
  for (let k = 0; k < limit; k++) {
    const h = hits[k];
    const d = S.docs[h.i];
    box.appendChild(resultCard(d, h.i, q, terms));
  }
  if (hits.length > limit) {
    const more = document.createElement('p');
    more.className = 'statusLine';
    more.textContent = '仅显示前 ' + limit + ' 条，共 ' + hits.length + ' 条。输入更具体的词可缩小范围。';
    box.appendChild(more);
  }
}

function resultCard(d, idx, q, terms) {
  const card = document.createElement('button');
  card.type = 'button';
  card.className = 'card';

  const head = document.createElement('div');
  head.className = 'cardHead';
  const no = document.createElement('span');
  no.className = 'cardNo';
  no.textContent = d.no || ('#' + (d.seq || 0));
  head.appendChild(no);
  const t = document.createElement('span');
  t.className = 'cardTitle';
  t.innerHTML = hlHtml(d.title || '(无标题)', terms);
  head.appendChild(t);
  if (d.src === 'extra') {
    const tag = document.createElement('span');
    tag.className = 'cardNo';
    tag.textContent = '补充';
    head.appendChild(tag);
  }
  card.appendChild(head);

  const meta = document.createElement('div');
  meta.className = 'cardMeta';
  meta.textContent = [d.chapter, d.meta, d.chars ? d.chars + '字' : ''].filter(Boolean).join(' · ');
  card.appendChild(meta);

  const sn = document.createElement('div');
  sn.className = 'snip';
  sn.innerHTML = snippet(d, q, S.mode);
  card.appendChild(sn);

  card.addEventListener('click', () => openReader(idx, q));
  return card;
}

function renderToc() {
  if (!S.lite) return;
  const box = $('#tocList');
  const kw = ($('#tocFilter').value || '').trim().toLowerCase();
  box.innerHTML = '';
  let total = 0;
  S.lite.chapters.forEach((ch) => {
    const items = ch.items.filter((it) =>
      !kw || (it.title + it.no).toLowerCase().indexOf(kw) !== -1
    );
    if (!items.length) return;
    total += items.length;
    const g = document.createElement('div');
    g.className = 'chapGroup';
    const h = document.createElement('div');
    h.className = 'chapTitle';
    h.textContent = ch.chapter + '（' + items.length + '）';
    g.appendChild(h);
    items.forEach((it) => {
      const c = document.createElement('button');
      c.type = 'button';
      c.className = 'card';
      const head = document.createElement('div');
      head.className = 'cardHead';
      const no = document.createElement('span');
      no.className = 'cardNo';
      no.textContent = it.no || ('#' + it.seq);
      head.appendChild(no);
      const t = document.createElement('span');
      t.className = 'cardTitle';
      t.textContent = it.title;
      head.appendChild(t);
      c.appendChild(head);
      const sn = document.createElement('div');
      sn.className = 'snip';
      sn.textContent = it.summary || '';
      c.appendChild(sn);
      c.addEventListener('click', () => {
        const idx = S.docs.findIndex((d) => d.id === it.id);
        if (idx >= 0) openReader(idx, '');
        else toast('全文还在加载，请稍候再试');
      });
      g.appendChild(c);
    });
    box.appendChild(g);
  });
  if (!total) {
    box.innerHTML = '<p class="emptyNote">没有匹配的标题</p>';
  }
}

/* ---------------- 阅读器 ---------------- */
function openReader(idx, q) {
  const d = S.docs[idx];
  if (!d) return;
  S.readerIdx = idx;
  document.body.style.overflow = 'hidden';
  $('#readerTitle').textContent = (d.no ? d.no + ' ' : '') + d.title;
  const body = $('#readerBody');
  const terms = q ? hlTerms(q, S.mode) : [];
  const hitPos = q ? firstHitPos(d, q) : -1;

  let html = '<h2>' + (terms.length ? hlHtml(d.title, terms) : esc(d.title)) + '</h2>';
  if (d.meta) html += '<div class="rMeta">' + esc(d.meta) + '</div>';

  if (d.src === 'extra') {
    html += '<div class="rBody">' + (terms.length ? hlHtml(d.fullText, terms) : esc(d.fullText))
      .replace(/\n/g, '<br>') + '</div>';
  } else {
    d.sections.forEach((s) => {
      if (s.h) {
        html += '<h3' + (hitPos >= 0 ? ' id="hitAnchor"' : '') + '>'
          + (terms.length ? hlHtml(s.h, terms) : esc(s.h)) + '</h3>';
      }
      s.b.forEach((b) => {
        if (b.t === 'p') {
          html += '<p>' + (terms.length ? hlHtml(b.v, terms) : esc(b.v)) + '</p>';
        } else if (b.t === 'table') {
          const rows = b.v || [];
          if (!rows.length) return;
          // 列宽：优先用数据里带的 w（从 Word 表格列宽换算的百分比）
          const ncol = rows.reduce((m, r) => Math.max(m, (r || []).length), 0);
          const wArr = Array.isArray(b.w) && b.w.length === ncol ? b.w : null;
          // 第一列全是短标签（≤6 字）时才禁止换行；长文本必须允许换行，否则会被撑爆
          const narrowFirst = rows.every((r) => !r || !r[0] || String(r[0]).length <= 6);
          const minW = ncol <= 2 ? 300 : (ncol === 3 ? 420 : 520);
          html += '<div class="tblWrap"><table'
            + (wArr ? ' class="tblFixed"' : '')
            + (narrowFirst ? ' data-narrowfirst="1"' : '')
            + ' style="min-width:' + minW + 'px">'
            + (wArr ? '<colgroup>'
                + wArr.map((p) => '<col style="width:' + p + '%">').join('')
                + '</colgroup>' : '')
            + '<tbody>';
          rows.forEach((row, ri) => {
            html += '<tr>';
            (row || []).forEach((cell) => {
              const tag = ri === 0 ? 'th' : 'td';
              const txt = terms.length ? hlHtml(cell, terms) : esc(cell);
              html += '<' + tag + '>' + txt + '</' + tag + '>';
            });
            html += '</tr>';
          });
          html += '</tbody></table></div>';
        }
      });
    });
  }

  body.innerHTML = html;
  $('#reader').hidden = false;
  body.scrollTop = 0;

  // 定位到命中处
  if (hitPos >= 0) {
    requestAnimationFrame(() => {
      const marks = $$('mark', body);
      if (marks.length) {
        marks[0].classList.add('hitLine');
        marks[0].scrollIntoView({ block: 'center' });
      }
    });
  }
  updateNavBtns();
}

function closeReader() {
  $('#reader').hidden = true;
  document.body.style.overflow = '';
}

function updateNavBtns() {
  $('#btnPrev').disabled = S.readerIdx <= 0;
  $('#btnNext').disabled = S.readerIdx >= S.docs.length - 1;
  $('#btnPrev').style.opacity = S.readerIdx <= 0 ? '.4' : '1';
  $('#btnNext').style.opacity = S.readerIdx >= S.docs.length - 1 ? '.4' : '1';
}

function stepReader(delta) {
  const n = S.readerIdx + delta;
  if (n < 0 || n >= S.docs.length) return;
  openReader(n, S.query);
}

async function copyCurrent() {
  const d = S.docs[S.readerIdx];
  if (!d) return;
  const text = ((d.no ? d.no + ' ' : '') + d.title + '\n\n' + d.fullText);
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制全文');
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast('已复制全文'); }
    catch (e2) { toast('复制失败，请手动选择文本'); }
    document.body.removeChild(ta);
  }
}

/* ---------------- 补充内容 ---------------- */
function extraToDoc(x) {
  return {
    id: x.id, chapter: '我的补充', no: '', title: x.title || '未命名补充',
    meta: '添加于 ' + new Date(x.createdAt || Date.now()).toLocaleString('zh-CN'),
    seq: 0, gseq: 900000 + (x.createdAt || 0) % 100000,
    sections: [], src: 'extra', chars: (x.content || '').length,
    fullText: (x.title || '') + '\n' + (x.content || ''),
    raw: x,
  };
}

async function loadExtras() {
  S.extras = await DB.all();
  S.extras.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  rebuildExtraDocs();
  renderStats();
  renderExtraList();
}

/** 把补充内容并入 S.docs（放在正文之后） */
function rebuildExtraDocs() {
  S.docs = S.docs.filter((d) => d.src !== 'extra').concat(S.extras.map(extraToDoc));
}

function renderExtraList() {
  const box = $('#extraList');
  box.innerHTML = '';
  if (!S.extras.length) {
    box.innerHTML = '<p class="emptyNote">还没有补充内容。<br>点上方按钮，把新的文字贴进来即可参与搜索。</p>';
    return;
  }
  S.extras.forEach((x) => {
    const el = document.createElement('div');
    el.className = 'extraItem';
    const head = document.createElement('div');
    head.className = 'extraItemHead';
    const left = document.createElement('div');
    left.style.minWidth = '0';
    const t = document.createElement('p');
    t.className = 'extraItemTitle';
    t.textContent = x.title || '未命名补充';
    left.appendChild(t);
    const m = document.createElement('div');
    m.className = 'extraItemMeta';
    m.textContent = (x.content || '').length + ' 字 · '
      + new Date(x.createdAt || Date.now()).toLocaleString('zh-CN');
    left.appendChild(m);
    head.appendChild(left);

    const ops = document.createElement('div');
    ops.className = 'extraItemOps';
    const bView = document.createElement('button');
    bView.type = 'button';
    bView.className = 'miniBtn';
    bView.textContent = '查看';
    bView.addEventListener('click', () => {
      const idx = S.docs.findIndex((d) => d.id === x.id);
      if (idx >= 0) openReader(idx, ''); else toast('尚未纳入索引，请刷新页面');
    });
    const bDel = document.createElement('button');
    bDel.type = 'button';
    bDel.className = 'miniBtn';
    bDel.textContent = '删除';
    bDel.style.color = '#c0392b';
    bDel.addEventListener('click', () => delExtra(x.id));
    ops.appendChild(bView);
    ops.appendChild(bDel);
    head.appendChild(ops);
    el.appendChild(head);

    const b = document.createElement('div');
    b.className = 'extraItemBody';
    b.textContent = (x.content || '').slice(0, 300);
    el.appendChild(b);
    box.appendChild(el);
  });
}

async function delExtra(id) {
  if (!window.confirm('确定删除这条补充内容？')) return;
  await DB.del(id);
  await loadExtras();
  if (S.ready) await buildIndex();
  toast('已删除');
}

function openSheet() {
  $('#sheet').hidden = false;
  $('#sheetMask').hidden = false;
  $('#fTitle').value = '';
  $('#fBody').value = '';
  $('#fileName').textContent = '支持 txt / md / docx';
  $('#fFile').value = '';
  setTimeout(() => $('#fTitle').focus(), 120);
}

function closeSheet() {
  $('#sheet').hidden = true;
  $('#sheetMask').hidden = true;
}

async function saveExtra() {
  const title = $('#fTitle').value.trim();
  const content = $('#fBody').value.trim();
  if (!content) { toast('请先填写正文内容'); return; }
  const item = {
    id: 'x_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
    title: title || (content.slice(0, 20) + (content.length > 20 ? '…' : '')),
    content,
    createdAt: Date.now(),
  };
  const ok = await DB.put(item);
  if (!ok) { toast('保存失败：浏览器存储不可用'); return; }
  await loadExtras();
  if (S.ready) await buildIndex();
  closeSheet();
  toast('已保存，可立即搜到');
}

/* docx 解析：按需加载 mammoth */
function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error('加载失败'));
    document.head.appendChild(s);
  });
}

async function handleFile(file) {
  if (!file) return;
  const name = file.name.toLowerCase();
  $('#fileName').textContent = '正在读取 ' + file.name;
  try {
    if (name.endsWith('.docx')) {
      if (!window.mammoth) {
        await loadScript('https://cdn.jsdelivr.net/npm/mammoth@1.8.0/mammoth.browser.min.js');
      }
      const buf = await file.arrayBuffer();
      const res = await window.mammoth.extractRawText({ arrayBuffer: buf });
      const text = (res.value || '').replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
      if (!text) throw new Error('文档没有可提取的文字');
      $('#fBody').value = text;
      if (!$('#fTitle').value.trim()) $('#fTitle').value = file.name.replace(/\.docx$/i, '');
      $('#fileName').textContent = '已导入 ' + text.length + ' 字';
    } else if (name.endsWith('.json')) {
      const text = await file.text();
      const data = JSON.parse(text);
      await importBackup(data);
      return;
    } else {
      const text = await file.text();
      $('#fBody').value = text;
      if (!$('#fTitle').value.trim()) $('#fTitle').value = file.name.replace(/\.\w+$/, '');
      $('#fileName').textContent = '已导入 ' + text.length + ' 字';
    }
  } catch (e) {
    $('#fileName').textContent = '读取失败：' + e.message;
    toast('文件读取失败，可直接粘贴文字');
  }
}

function exportBackup() {
  if (!S.extras.length) { toast('没有可导出的内容'); return; }
  const blob = new Blob([JSON.stringify({ type: 'notes-extra-backup', version: 1, items: S.extras }, null, 2)],
    { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '笔记补充备份-' + new Date().toISOString().slice(0, 10) + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
  toast('已导出 ' + S.extras.length + ' 条');
}

async function importBackup(data) {
  const items = data && Array.isArray(data.items) ? data.items : null;
  if (!items) { toast('备份文件格式不正确'); return; }
  let n = 0;
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    if (!it || !it.content) continue;
    const rec = {
      id: it.id || ('x_' + Date.now() + '_' + i),
      title: it.title || '',
      content: it.content,
      createdAt: it.createdAt || Date.now(),
    };
    if (await DB.put(rec)) n++;
  }
  await loadExtras();
  if (S.ready) await buildIndex();
  closeSheet();
  toast('已导入 ' + n + ' 条');
}

/* ---------------- 交互绑定 ---------------- */
let debounceTimer = null;
function onInput() {
  const q = $('#q').value;
  S.query = q;
  $('#btnClear').hidden = !q;
  clearTimeout(debounceTimer);
  if (!q.trim()) {
    showHome();
    $('#status').textContent = '';
    return;
  }
  debounceTimer = setTimeout(() => {
    doSearch();
    pushHist(q.trim());
  }, S.mode === 'fuzzy' ? 180 : 130);
}

function switchView(name) {
  ['Search', 'Toc', 'Extra'].forEach((v) => {
    const el = $('#view' + v);
    if (el) el.hidden = (v !== name);
  });
  $$('.tab').forEach((t) => t.classList.toggle('isOn', t.dataset.view === name));
  window.scrollTo(0, 0);
}

function bind() {
  $('#lockForm').addEventListener('submit', submitLock);
  $('#btnLock').addEventListener('click', lockNow);
  $('#btnTheme').addEventListener('click', toggleTheme);
  $('#btnAdd').addEventListener('click', openSheet);
  $('#btnAdd2').addEventListener('click', openSheet);
  $('#btnCloseSheet').addEventListener('click', closeSheet);
  $('#btnCancelSheet').addEventListener('click', closeSheet);
  $('#sheetMask').addEventListener('click', closeSheet);
  $('#btnSave').addEventListener('click', saveExtra);
  $('#fFile').addEventListener('change', (e) => handleFile(e.target.files && e.target.files[0]));

  $('#btnExport').addEventListener('click', exportBackup);
  $('#btnImport').addEventListener('click', () => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.json,application/json';
    inp.addEventListener('change', async () => {
      const f = inp.files && inp.files[0];
      if (!f) return;
      try { await importBackup(JSON.parse(await f.text())); }
      catch (e) { toast('导入失败：不是有效的备份文件'); }
    });
    inp.click();
  });

  $('#q').addEventListener('input', onInput);
  $('#q').addEventListener('search', onInput);
  $('#q').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $('#q').blur(); clearTimeout(debounceTimer); doSearch(); }
  });
  $('#btnClear').addEventListener('click', () => {
    $('#q').value = '';
    onInput();
    $('#q').focus();
  });

  $$('.modeBtn').forEach((b) => {
    b.addEventListener('click', () => {
      S.mode = b.dataset.mode;
      $$('.modeBtn').forEach((x) => {
        const on = x === b;
        x.classList.toggle('isOn', on);
        x.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      $('#modeHint').textContent = S.mode === 'exact'
        ? '整句完整匹配，结果最准'
        : '容忍错字与语序变化，结果更全';
      if (S.query.trim()) { clearTimeout(debounceTimer); doSearch(); }
    });
  });

  $$('.tab').forEach((t) => {
    t.addEventListener('click', () => switchView(t.dataset.view));
  });

  $('#tocFilter').addEventListener('input', renderToc);

  $('#btnBack').addEventListener('click', closeReader);
  $('#btnPrev').addEventListener('click', () => stepReader(-1));
  $('#btnNext').addEventListener('click', () => stepReader(1));
  $('#btnCopy').addEventListener('click', copyCurrent);
  $('#btnFontUp').addEventListener('click', () => {
    const cur = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--reader-font'), 10) || 17;
    applyFont(Math.min(26, cur + 2));
  });
  $('#btnFontDown').addEventListener('click', () => {
    const cur = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--reader-font'), 10) || 17;
    applyFont(Math.max(13, cur - 2));
  });

  $('#btnClearHist').addEventListener('click', () => {
    S.history = [];
    LS.set('nb_hist', []);
    renderHist();
  });

  // 左滑返回（阅读器）
  let x0 = null;
  const rb = $('#readerBody');
  rb.addEventListener('touchstart', (e) => { x0 = e.touches[0].clientX; }, { passive: true });
  rb.addEventListener('touchend', (e) => {
    if (x0 === null) return;
    const dx = e.changedTouches[0].clientX - x0;
    if (dx > 70 && Math.abs(dx) > Math.abs(e.changedTouches[0].clientY - (e.changedTouches[0].clientY)) - 1) {
      closeReader();
    }
    x0 = null;
  }, { passive: true });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!$('#sheet').hidden) closeSheet();
      else if (!$('#reader').hidden) closeReader();
    }
  });

  window.addEventListener('popstate', () => {
    if (!$('#reader').hidden) closeReader();
  });
}

/* ---------------- 安装引导 ---------------- */
function setupInstallTip() {
  const ua = navigator.userAgent || '';
  const isIOS = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const isSafari = /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS|Chrome|Android/.test(ua);
  const isMacSafari = /Macintosh/.test(ua) && isSafari;
  const standalone = window.navigator.standalone === true
    || (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
  if (standalone) return;                       // 已安装，不打扰
  if (LS.get('nb_tip_off', false)) return;      // 用户已关闭

  let how = '';
  if (isIOS) how = 'Safari 里点底部「分享 ⊙」，选「添加到主屏幕」。之后可离线使用，像一个 App。';
  else if (isMacSafari) how = 'Safari 菜单「文件 → 添加到程序坞」，即可作为独立应用打开。';
  else if (/Android/.test(ua)) how = '浏览器菜单里选「安装应用」或「添加到主屏幕」。';
  else how = '浏览器地址栏右侧的「安装」图标，或菜单里的「添加到主屏幕」。';

  $('#installHow').textContent = how;
  $('#installTip').hidden = false;
  $('#btnHideTip').addEventListener('click', () => {
    $('#installTip').hidden = true;
    LS.set('nb_tip_off', true);
  });
}

/* ---------------- PWA ---------------- */
function registerSW() {
  if ('serviceWorker' in navigator && location.protocol.indexOf('http') === 0) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' })
        .then((reg) => { if (reg.waiting) reg.waiting.postMessage({ type: 'SKIP_WAITING' }); })
        .catch(() => { /* 忽略 */ });
    });
  }
}

/* ---------------- ?reset=1 强制清缓存 ----------------
   换了 .enc 却还是显示旧内容时，在网址后面加 ?reset=1 打开一次即可：
   清空 Cache Storage、注销 Service Worker、清掉记住的密钥，然后自动重载。 */
function handleResetFlag() {
  var u;
  try { u = new URL(location.href); } catch (e) { return; }
  if (u.searchParams.get('reset') !== '1') return;
  (async function () {
    try {
      if ('caches' in window) {
        var keys = await caches.keys();
        await Promise.all(keys.map(function (k) { return caches.delete(k); }));
      }
    } catch (e) { /* 忽略 */ }
    try {
      if ('serviceWorker' in navigator) {
        var regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map(function (r) { return r.unregister(); }));
      }
    } catch (e) { /* 忽略 */ }
    try { await DB.delKey('main'); await DB.delKey('mainExp'); } catch (e) { /* 忽略 */ }
    u.searchParams.delete('reset');
    location.replace(u.toString());
  })();
}

/* ---------------- 启动 ---------------- */
function init() {
  handleResetFlag();
  initTheme();
  initFont();
  bind();
  const daysEl = $('#lockDays');
  if (daysEl) daysEl.textContent = String(REMEMBER_DAYS);
  renderHot();
  renderHist();
  registerSW();
  setupInstallTip();
  loadData();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}