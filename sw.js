const CACHE_NAME = 'venscan-cache-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/index.css',
  '/app.js',
  '/site.webmanifest'
];

// Install Event: cache all static assets and skip waiting
self.addEventListener('install', (e) => {
  self.skipWaiting(); // Force the waiting service worker to become active immediately
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    })
  );
});

// Activate Event: clear old caches and claim clients
self.addEventListener('activate', (e) => {
  e.waitUntil(
    Promise.all([
      // Clean up old caches
      caches.keys().then((keys) => {
        return Promise.all(
          keys.map((key) => {
            if (key !== CACHE_NAME) {
              return caches.delete(key);
            }
          })
        );
      }),
      // Force active service worker to take control of open tabs immediately
      self.clients.claim()
    ])
  );
});

// Fetch Event: network fallback to cache, handle offline API calls
self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then((cachedResponse) => {
      return cachedResponse || fetch(e.request).catch((err) => {
        if (e.request.url.includes('/api/')) {
          return new Response(
            JSON.stringify({ 
              status: 'offline', 
              error: 'Offline mode active',
              message: 'You are currently offline. Cloud API checks are bypassed, local static checks remain functional.' 
            }),
            {
              status: 503,
              headers: { 'content-type': 'application/json' }
            }
          );
        }
        throw err;
      });
    })
  );
});
