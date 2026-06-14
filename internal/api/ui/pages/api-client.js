(() => {
  const MAX_RETRIES = 3;
  const BASE_DELAY_MS = 1000;
  let _reconnectingBanner = null;

  function showReconnectingBanner() {
    if (_reconnectingBanner) return;
    _reconnectingBanner = document.createElement('div');
    _reconnectingBanner.id = 'reconnect-banner';
    _reconnectingBanner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99999;background:rgba(251,191,36,0.95);color:#000;text-align:center;padding:8px 16px;font-size:13px;font-weight:500;transition:opacity 0.3s';
    _reconnectingBanner.textContent = 'Tentando reconectar a API...';
    document.body.appendChild(_reconnectingBanner);
  }

  function hideReconnectingBanner() {
    if (_reconnectingBanner) {
      _reconnectingBanner.style.opacity = '0';
      setTimeout(() => { _reconnectingBanner?.remove(); _reconnectingBanner = null; }, 300);
    }
  }

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  async function buildAuthHeaders(extra = {}) {
    const h = { ...extra };
    const tok = window.state._authAccessToken || window.localTokenGet();
    if (tok) h.Authorization = `Bearer ${tok}`;
    return h;
  }

  function handleAuthError() {
    window.localTokenClear();
    window.state._authAccessToken = null;
    window.state._dashboardStarted = false;
    window.showAuthGate();
  }

  async function fetchWithRetry(path, options = {}) {
    let lastErr;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        const res = await fetch(`${window.API}${path}`, options);
        if (res.status === 401) {
          handleAuthError();
          throw new Error('Session expired — sign in again');
        }
        if (!res.ok) {
          const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
          throw new Error(err.error || `HTTP ${res.status}`);
        }
        hideReconnectingBanner();
        return res;
      } catch (e) {
        lastErr = e;
        if (e.message?.startsWith('Session expired')) throw e;
        if (attempt < MAX_RETRIES) {
          if (attempt === 0) showReconnectingBanner();
          const delay = BASE_DELAY_MS * Math.pow(2, attempt);
          await sleep(delay);
        }
      }
    }
    hideReconnectingBanner();
    throw lastErr;
  }

  async function apiFetch(path) {
    const headers = await buildAuthHeaders();
    const res = await fetchWithRetry(path, { headers });
    return res.json();
  }

  async function apiPost(path, body, customHeaders = {}) {
    const headers = await buildAuthHeaders({ 'Content-Type': 'application/json', ...customHeaders });
    const res = await fetchWithRetry(path, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    return res.json();
  }

  async function apiDelete(path) {
    const headers = await buildAuthHeaders();
    const res = await fetchWithRetry(path, { method: 'DELETE', headers });
    return res.json();
  }

  window.ApiClientPage = {
    buildAuthHeaders,
    handleAuthError,
    apiFetch,
    apiPost,
    apiDelete,
  };
})();
