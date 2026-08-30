/* Service Worker：离线缓存，安装后无需联网即可搜索全部笔记 */
const VER = 'v3-enc';
const SHELL = [
  './',
  './index.html',
  './app.css',
  './app.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './index.enc',
  './full.enc',
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

  // 网络优先：在线时一律拿服务器上的最新版本，断网时才回落到缓存。
  // 这样站点文件一更新，访客刷新就能看到新内容，不用手动清缓存。
  e.respondWith(
    fetch(req)
      .then((r) => {
        if (r && r.ok) {
          const copy = r.clone();
          caches.open('notes-shell-' + VER).then((c) => c.put(req, copy));
        }
        return r;
      })
      .catch(() => caches.match(req).then((hit) => hit || caches.match('./index.html')))
  );
});
