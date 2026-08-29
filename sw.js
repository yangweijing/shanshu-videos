/* Service Worker：离线缓存，安装后无需联网即可搜索全部笔记 */
const VER = 'v2-enc';
const SHELL = [
  './',
  './index.html',
  './app.css',
  './app.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './data/index.enc',
  './data/full.enc',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open('notes-shell-' + VER)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting())
      .catch(() => { /* 单项失败不影响安装 */ })
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k.indexOf('notes-shell-') === 0 && k !== 'notes-shell-' + VER)
          .map((k) => caches['delete'](k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // 页面：网络优先，失败回落缓存，保证能拿到新版本
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).then((r) => {
        const copy = r.clone();
        caches.open('notes-shell-' + VER).then((c) => c.put('./index.html', copy));
        return r;
      }).catch(() => caches.match('./index.html').then((r) => r || caches.match('./')))
    );
    return;
  }

  // 静态资源与数据：缓存优先，后台更新
  e.respondWith(
    caches.match(req).then((hit) => {
      const net = fetch(req).then((r) => {
        if (r && r.ok) {
          const copy = r.clone();
          caches.open('notes-shell-' + VER).then((c) => c.put(req, copy));
        }
        return r;
      }).catch(() => hit);
      return hit || net;
    })
  );
});
