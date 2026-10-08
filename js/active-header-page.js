(() => {
  const currentPathSegment = window.location.pathname.split('/').pop();
  const currentFile = (currentPathSegment
    ? (currentPathSegment.includes('.') ? currentPathSegment : `${currentPathSegment}.html`)
    : 'Home.html').toLowerCase();
  const aliases = new Map([
    ['index.html', 'home.html'],
    ['', 'home.html']
  ]);
  const normalizedCurrent = aliases.get(currentFile) || currentFile;

  const applyCurrentPageMarker = () => {
    document.querySelectorAll('.nav-links a[href], nav a[href], .header-actions a[href]').forEach((link) => {
      const href = link.getAttribute('href');
      if (!href || href.startsWith('#') || /^(https?:|mailto:|tel:)/i.test(href)) return;

      const target = (href.split(/[?#]/)[0].split('/').pop() || 'home.html').toLowerCase();
      const normalizedTarget = aliases.get(target) || target;
      if (normalizedTarget !== normalizedCurrent) return;

      link.classList.add('is-current-page');
      link.setAttribute('aria-current', 'page');
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyCurrentPageMarker, { once: true });
  } else {
    applyCurrentPageMarker();
  }
})();
