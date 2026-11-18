/* Apex-Shield service worker.
   The triage itself needs no network: hashing, zip reading and manifest decoding
   are all local, so an installed Shield works on a plane. The queue tab only
   describes a server, it never calls one. */

const CACHE = 'apex-shield-v1';

const SHELL = [
  './',
  'index.html',
  'styles.css',
  'core.js',
  'apk.js',
  'app.js',
  'manifest.webmanifest',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/maskable-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // addAll fails the whole install if one file 404s, so add on its own.
      await Promise.all(SHELL.map((url) => cache.add(url).catch(() => {})));
      await self.skipWaiting();
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)));
      await self.clients.claim();
    })()
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  if (new URL(request.url).origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith(
      (async () => {
        try {
          const fresh = await fetch(request);
          const cache = await caches.open(CACHE);
          cache.put('index.html', fresh.clone());
          return fresh;
        } catch {
          const cache = await caches.open(CACHE);
          return (await cache.match('index.html')) || (await cache.match('./')) ||
            new Response('Apex-Shield is offline and the shell is not cached yet.', {
              status: 503,
              headers: { 'Content-Type': 'text/plain' },
            });
        }
      })()
    );
    return;
  }

  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE);
      const hit = await cache.match(request);
      if (hit) {
        fetch(request)
          .then((res) => { if (res && res.ok) cache.put(request, res.clone()); })
          .catch(() => {});
        return hit;
      }
      try {
        const res = await fetch(request);
        if (res && res.ok) cache.put(request, res.clone());
        return res;
      } catch {
        return new Response('Offline', { status: 503 });
      }
    })()
  );
});
