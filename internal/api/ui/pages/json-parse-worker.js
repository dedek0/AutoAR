/**
 * Web Worker for heavy JSON parsing + sorting operations.
 * Receives { id, data, sortKey } and returns { id, items } or { id, error }.
 */
self.onmessage = function(e) {
  const { id, data, sortKey } = e.data;
  try {
    let items;
    if (typeof data === 'string') {
      items = JSON.parse(data);
    } else {
      items = data;
    }
    if (Array.isArray(items) && sortKey && items.length > 0 && items[0][sortKey] !== undefined) {
      items.sort((a, b) => {
        const av = a[sortKey], bv = b[sortKey];
        if (typeof av === 'string') return av.localeCompare(bv);
        return (av || 0) - (bv || 0);
      });
    }
    self.postMessage({ id, items });
  } catch (err) {
    self.postMessage({ id, error: err.message });
  }
};
