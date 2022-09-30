window.addEventListener('load', async () => {
  await navigator.serviceWorker.register('/sw.js');
});
