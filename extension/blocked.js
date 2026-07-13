// CyberShield Blocked Page Script
document.addEventListener('DOMContentLoaded', () => {
  const urlDisplay = document.getElementById('target-url-display');
  const backBtn = document.getElementById('btn-back');
  const proceedBtn = document.getElementById('btn-proceed');

  // Parse the target URL from the query parameter
  const queryParams = new URLSearchParams(window.location.search);
  const targetUrl = queryParams.get('url');

  if (targetUrl) {
    urlDisplay.textContent = `URL: ${targetUrl}`;
  } else {
    urlDisplay.textContent = '';
  }

  // Go Back to Safety Handler
  backBtn.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      // If there is no tab history, close the window/tab
      window.close();
    }
  });

  // Proceed Anyway (Unsafe) Handler
  proceedBtn.addEventListener('click', () => {
    if (!targetUrl) return;

    try {
      const hostname = new URL(targetUrl).hostname.replace('www.', '').toLowerCase();

      // Add to bypassed list in storage
      chrome.storage.local.get(['bypassedDomains'], (data) => {
        const bypassed = data.bypassedDomains || [];
        if (!bypassed.includes(hostname)) {
          bypassed.push(hostname);
          chrome.storage.local.set({ bypassedDomains: bypassed }, () => {
            // Once saved, navigate directly to target URL
            window.location.href = targetUrl;
          });
        } else {
          window.location.href = targetUrl;
        }
      });
    } catch (err) {
      console.error('Failed to bypass block:', err);
    }
  });
});
