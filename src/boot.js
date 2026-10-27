// Inside the desktop app, read the Markdown folder and settings first,
// then start the app with them in window.BOOT. In a plain browser, start right away.
(async () => {
  const T = window.__TAURI__ && window.__TAURI__.core;
  if (T) {
    try { window.BOOT = await T.invoke('load_all'); }
    catch (e) { window.BOOT = { error: String(e) }; }
  }
  const s = document.createElement('script');
  s.src = 'app.js';
  document.body.appendChild(s);
})();
