(function () {
  var STORAGE_KEY = 'ops-theme';
  var DEFAULT    = 'dark';

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) {}
  }

  function getPreferred() {
    try {
      var stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'dark' || stored === 'light') return stored;
    } catch (e) {}
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : DEFAULT;
  }

  // Apply immediately (before first paint)
  applyTheme(getPreferred());

  // Handle toggle clicks
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-theme-toggle]');
    if (!btn) return;
    var current = document.documentElement.getAttribute('data-theme') || DEFAULT;
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });
}());
