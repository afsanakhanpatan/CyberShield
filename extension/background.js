// CyberShield Background Service Worker
// Proxies backend API requests to bypass Chrome's Private Network Access (PNA) restrictions.

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'fetch_api') {
    const fetchOptions = {
      method: request.method || 'GET',
      headers: request.headers || {}
    };

    if (request.body) {
      fetchOptions.body = JSON.stringify(request.body);
    }

    console.log(`[CyberShield Proxy] Dispatching request to: ${request.url} via ${fetchOptions.method}`);

    fetch(request.url, fetchOptions)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log(`[CyberShield Proxy] Success from: ${request.url}`, data);
        sendResponse({ success: true, data });
      })
      .catch((error) => {
        console.error(`[CyberShield Proxy] Error for: ${request.url}`, error);
        sendResponse({ success: false, error: error.message });
      });

    return true; // Keep response channel open for asynchronous reply
  }
});

// Intercept navigation events to block malicious domains
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // Only block main tab navigation
  
  const url = details.url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  
  // Don't block our own extension pages (including blocked.html)
  if (url.startsWith(chrome.runtime.getURL(''))) return;

  try {
    const hostname = new URL(url).hostname.replace('www.', '').toLowerCase();
    
    chrome.storage.local.get(['blockedDomains', 'bypassedDomains'], (data) => {
      const blocked = data.blockedDomains || [];
      const bypassed = data.bypassedDomains || [];
      
      if (blocked.includes(hostname) && !bypassed.includes(hostname)) {
        // Redirect to warning page
        const redirectUrl = chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(url)}`);
        chrome.tabs.update(details.tabId, { url: redirectUrl });
      }
    });
  } catch (err) {
    console.error('Error in navigation blocker:', err);
  }
});
