const CACHE_NAME = 'venscan-cache-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/index.css',
  '/app.js',
  '/site.webmanifest'
];

// Install Event: cache all static assets
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    })
  );
});

// Activate Event: clear old caches
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
});

// Fetch Event: network fallback to cache, handle offline API calls
self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then((cachedResponse) => {
      // Return cached asset if found, otherwise perform network fetch
      return cachedResponse || fetch(e.request).catch((err) => {
        // If offline and request is an API endpoint, return structured JSON fallback
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
