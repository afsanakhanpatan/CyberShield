// CyberShield Extension Popup Logic

document.addEventListener('DOMContentLoaded', async () => {
  const scannedEl = document.getElementById('stat-scanned');
  const threatsEl = document.getElementById('stat-threats');
  const listEl = document.getElementById('detection-list');
  const backendInput = document.getElementById('backend-url');
  const saveBtn = document.getElementById('save-settings');

  // Load config and stats
  chrome.storage.local.get(['backendUrl', 'totalScanned', 'threatsBlocked', 'recentDetections'], (data) => {
    if (data.backendUrl) {
      backendInput.value = data.backendUrl;
    }
    scannedEl.innerText = data.totalScanned || 0;
    threatsEl.innerText = data.threatsBlocked || 0;

    if (data.recentDetections && data.recentDetections.length > 0) {
      listEl.innerHTML = '';
      data.recentDetections.slice(-5).reverse().forEach(threat => {
        const item = document.createElement('div');
        item.className = 'detection-item';
        item.innerHTML = `
          <div class="detection-details">
            <span class="detection-category">${escapeHtml(threat.category)}</span>
            <span class="detection-val" title="${escapeHtml(threat.target)}">${escapeHtml(threat.target)}</span>
          </div>
          <span class="detection-badge">BLOCKED</span>
        `;
        listEl.appendChild(item);
      });
    }
  });

  // Save Settings
  saveBtn.addEventListener('click', () => {
    const url = backendInput.value.trim();
    if (url) {
      chrome.storage.local.set({ backendUrl: url }, () => {
        saveBtn.innerText = 'Configuration Saved ✓';
        saveBtn.style.background = 'linear-gradient(135deg, #10b981, #059669)';
        setTimeout(() => {
          saveBtn.innerText = 'Save Config';
          saveBtn.style.background = 'linear-gradient(135deg, var(--cyan), #0891b2)';
        }, 1500);
      });
    }
  });
});

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
