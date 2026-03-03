(() => {
  const STORAGE_KEY = 'newsletterPopupLastShown';

  function todayString() {
    const d = new Date();
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }

  function getLastShown() {
    return localStorage.getItem(STORAGE_KEY);
  }

  function setLastShown(value) {
    try { localStorage.setItem(STORAGE_KEY, value); } catch (e) {}
  }

  function shouldShow() {
    const last = getLastShown();
    return last !== todayString();
  }

  function showPopup() {
    const root = document.getElementById('newsletter-popup');
    if (!root) return;
    root.setAttribute('aria-hidden', 'false');
    const email = root.querySelector('input[type="email"]');
    if (email) email.focus();
  }

  function hidePopup(record = true) {
    const root = document.getElementById('newsletter-popup');
    if (!root) return;
    root.setAttribute('aria-hidden', 'true');
    if (record) setLastShown(todayString());
  }

  document.addEventListener('DOMContentLoaded', () => {
    const root = document.getElementById('newsletter-popup');
    if (!root) return;

    // Wire up close / overlay / later buttons
    root.addEventListener('click', (ev) => {
      const action = ev.target.getAttribute && ev.target.getAttribute('data-action');
      if (action === 'close' || ev.target.classList.contains('popup-close')) {
        hidePopup(true);
      }
    });

    const laterBtn = root.querySelector('[data-action="later"]');
    if (laterBtn) laterBtn.addEventListener('click', () => hidePopup(true));

    // On submit, record shown today so we don't show again until next day
    const form = root.querySelector('form');
    if (form) {
      form.addEventListener('submit', () => setLastShown(todayString()));
    }

    if (shouldShow()) showPopup();
  });
})();
