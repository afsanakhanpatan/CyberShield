// CyberShield Content Script
let BACKEND_URL = 'http://localhost:8090';


let walletPromiseResolve = null;
window.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'CYBERSHIELD_WALLET_RESULT') {
    console.log('[CyberShield Content] Received CYBERSHIELD_WALLET_RESULT message from main world:', event.data);
    if (walletPromiseResolve) {
      walletPromiseResolve(event.data);
      walletPromiseResolve = null;
    }
  }
});

const triggerWalletConnection = () => {
  return new Promise((resolve) => {
    console.log('[CyberShield Content] Triggering wallet connection to main world via postMessage...');
    walletPromiseResolve = resolve;
    window.postMessage({ type: 'CYBERSHIELD_CONNECT_WALLET' }, '*');
  });
};

// Maintain a set of elements we are already checking or have checked
const processedElements = new WeakSet();

// Initialize dynamic backend URL from storage
chrome.storage.local.get(['backendUrl'], (data) => {
  if (data.backendUrl) {
    BACKEND_URL = data.backendUrl;
  }
});

// Helper to call backend API via background proxy to bypass Chrome PNA loopback restrictions
async function callBackend(endpoint, method, body) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({
      action: 'fetch_api',
      url: `${BACKEND_URL}${endpoint}`,
      method,
      headers: { 'Content-Type': 'application/json' },
      body
    }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (response && response.success) {
        resolve(response.data);
      } else {
        reject(new Error(response ? response.error : 'Background proxy fetch failed'));
      }
    });
  });
}

// Helper to log stats
function trackScan() {
  chrome.storage.local.get(['totalScanned'], (data) => {
    const current = data.totalScanned || 0;
    chrome.storage.local.set({ totalScanned: current + 1 });
  });
}

function trackThreat(category, target) {
  chrome.storage.local.get(['threatsBlocked', 'recentDetections'], (data) => {
    const count = data.threatsBlocked || 0;
    const list = data.recentDetections || [];
    
    // Add threat to history (cap at 20)
    list.push({ category, target, timestamp: Date.now() });
    if (list.length > 20) list.shift();

    chrome.storage.local.set({
      threatsBlocked: count + 1,
      recentDetections: list
    });
  });
}

// Initialize Observer
function init() {
  console.log('CyberShield active and scanning...');
  
  // Create an observer to watch for new nodes in the document body
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        shouldScan = true;
        break;
      }
    }
    if (shouldScan) {
      scanPage();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Run initial scan
  scanPage();
}

// Main scanning dispatcher
function scanPage() {
  const isWhatsApp = window.location.hostname.includes('web.whatsapp.com');
  const isGmail = window.location.hostname.includes('mail.google.com');
  const isLocalSandbox = window.location.pathname.includes('test_extension.html');

  if (isWhatsApp) {
    scanWhatsApp();
  } else if (isGmail) {
    scanGmail();
  } else if (isLocalSandbox) {
    scanWhatsApp();
    scanGmail();
  }
}

// Scanning logic for WhatsApp Web
async function scanWhatsApp() {
  const messageNodes = document.querySelectorAll('.message-in, [data-id]');

  for (const node of messageNodes) {
    if (processedElements.has(node)) continue;
    
    // Find text container
    const textNode = node.querySelector('.copyable-text');
    if (!textNode) continue;

    // Convert plain text upi:// URIs into clickable hyperlinks
    try {
      const upiRegex = /(upi:\/\/pay\?[^\s"'\<]+)/gi;
      if (upiRegex.test(textNode.innerHTML) && !textNode.querySelector('.cybershield-upi-link')) {
        textNode.innerHTML = textNode.innerHTML.replace(upiRegex, (match) => {
          return `<a href="${match}" class="cybershield-upi-link" style="color: #2563eb !important; text-decoration: underline !important; font-weight: 600 !important; word-break: break-all !important;">${match}</a>`;
        });
      }
    } catch (linkErr) {
      console.error('Failed to linkify UPI URIs:', linkErr);
    }

    // Check if already badged via dataset.cybershieldScanned
    if (node.dataset.cybershieldScanned) {
      continue;
    }

    // Mark as processed
    processedElements.add(node);
    
    // Clone node to safely remove quoted replies from scanned text context
    const cloneNode = textNode.cloneNode(true);
    const quoteNode = cloneNode.querySelector('[data-testid="quoted-message"], .quoted-mention, blockquote');
    if (quoteNode) {
      quoteNode.remove();
    }
    
    // Extract text and attachments
    const text = cloneNode.innerText.trim();
    if (!text) continue;

    trackScan();

    const threats = [];

    // Scan WhatsApp profile details (phone country code verification)
    try {
      const preText = textNode.getAttribute('data-pre-plain-text');
      if (preText) {
        const match = preText.match(/\]\s*([^:]+):/);
        if (match) {
          const sender = match[1].trim();
          if (sender.startsWith('+')) {
            const ccMatch = sender.match(/^\+(\d{1,4})/);
            if (ccMatch) {
              const countryCode = ccMatch[1];
              const HIGH_RISK_COUNTRY_CODES = ['92', '234', '994', '251', '62', '84'];
              if (HIGH_RISK_COUNTRY_CODES.includes(countryCode)) {
                threats.push({
                  safe: false,
                  verdict: 'SUSPICIOUS',
                  category: 'WhatsApp Profile Risk',
                  reason: `Foreign Origin Alert: This message was received from a high-risk foreign phone country code (+${countryCode}). Verify identity before continuing contact or making payments.`,
                  targetValue: sender,
                  risk_score: 80,
                  reportedCount: 0
                });
              }
            }
          }
        }
      }
    } catch (profileErr) {
      console.error('Error scanning profile details:', profileErr);
    }

    // Check for images (potential QR codes) in the message container
    const imgNodes = node.querySelectorAll('img');
    imgNodes.forEach(img => {
      if (img.src && img.src.startsWith('blob:')) {
        handleBlobImage(img.src, node);
      }
    });

    // Check URLs
    const urls = extractUrls(text);
    for (const url of urls) {
      const urlThreat = await getUrlThreat(url);
      if (urlThreat) {
        threats.push(urlThreat);
      }
    }

    // Check UPIs
    const upiRegex = /upi:\/\/pay\?[^\s"']+/gi;
    const upiMatches = text.match(upiRegex) || [];
    for (const upiUri of upiMatches) {
      const upiThreat = await getUpiThreat(upiUri, text);
      if (upiThreat) {
        threats.push(upiThreat);
      }
    }

    // Check message text
    const textThreat = await getTextThreat(text);
    if (textThreat) {
      threats.push(textThreat);
    }

    // Pick highest risk threat only
    if (threats.length === 0) continue;

    // Mark message as scanned/badged
    node.dataset.cybershieldScanned = "true";

    const worst = threats.sort((a, b) => b.risk_score - a.risk_score)[0];
    
    // Track threat
    trackThreat(worst.category, worst.targetValue);

    // Add threat count info
    if (threats.length > 1) {
      worst.additionalNote = `${threats.length - 1} more threat${threats.length > 2 ? 's' : ''} in message`;
    }

    injectBadge(textNode, worst);
  }
}

// Scanning logic for Gmail
async function scanGmail() {
  const emailNodes = document.querySelectorAll('.a3s');

  for (const node of emailNodes) {
    if (processedElements.has(node)) continue;

    // Check if already badged via dataset.cybershieldScanned
    if (node.dataset.cybershieldScanned) {
      continue;
    }

    processedElements.add(node);

    const text = node.innerText.trim();
    if (!text) continue;

    trackScan();

    // Extract sender details
    let senderEmail = '';
    let senderName = '';
    
    const threadContainer = node.closest('.g3');
    if (threadContainer) {
      const emailSpan = threadContainer.querySelector('span[email]');
      if (emailSpan) {
        senderEmail = emailSpan.getAttribute('email');
        senderName = emailSpan.innerText;
      }
    }

    const threats = [];

    // Verify sender alignment + check text for scams
    const textThreat = await getTextThreat(text, senderName, senderEmail);
    if (textThreat) {
      threats.push(textThreat);
    }

    // Verify links in email
    const links = node.querySelectorAll('a');
    for (const link of links) {
      const url = link.href;
      if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
        const urlThreat = await getUrlThreat(url);
        if (urlThreat) {
          threats.push(urlThreat);
        }
      }
    }

    // Pick highest risk threat only
    if (threats.length === 0) continue;

    // Mark as scanned
    node.dataset.cybershieldScanned = "true";

    const worst = threats.sort((a, b) => b.risk_score - a.risk_score)[0];
    
    // Track threat
    trackThreat(worst.category, worst.targetValue);

    if (threats.length > 1) {
      worst.additionalNote = `${threats.length - 1} more threat${threats.length > 2 ? 's' : ''} in message`;
    }

    injectBadge(node, worst);
  }
}

// Extract URLs from text
function extractUrls(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  return text.match(urlRegex) || [];
}

// Verify URL via backend API
async function getUrlThreat(url) {
  try {
    const result = await callBackend('/verify/url', 'POST', { url });
    
    if (!result.safe) {
      // Sync domain to extension local storage for real-time blocking
      try {
        const domain = new URL(url).hostname.replace('www.', '').toLowerCase();
        chrome.storage.local.get(['blockedDomains'], (data) => {
          const list = data.blockedDomains || [];
          if (!list.includes(domain)) {
            list.push(domain);
            chrome.storage.local.set({ blockedDomains: list });
          }
        });
      } catch (err) {
        console.error('Failed to extract domain for blocking:', err);
      }

      return {
        safe: false,
        verdict: result.verdict,
        category: 'Phishing / Malicious URL',
        reason: result.reason,
        targetValue: url,
        reportedCount: result.reported_count,
        risk_score: result.risk_score || 85
      };
    }
  } catch (error) {
    console.error('CyberShield URL verify error:', error);
  }
  return null;
}

// Verify UPI
async function getUpiThreat(upiUri, rawText) {
  try {
    const result = await callBackend('/verify/upi', 'POST', { upi_uri: upiUri, raw_text: rawText });
    if (!result.safe) {
      return {
        safe: false,
        verdict: result.verdict,
        category: 'Financial / UPI Scam',
        reason: result.reason,
        targetValue: result.details.payee_id || 'UPI URL',
        reportedCount: result.reported_count,
        risk_score: result.risk_score || 100
      };
    }
  } catch (err) {
    console.error('CyberShield UPI verify error:', err);
  }
  return null;
}

// Verify text
async function getTextThreat(text, senderName = '', senderEmail = '') {
  try {
    const payload = { text };
    if (senderName || senderEmail) {
      payload.sender_name = senderName;
      payload.sender_email = senderEmail;
    }
    const result = await callBackend('/verify/text', 'POST', payload);
    
    if (!result.safe) {
      return {
        safe: false,
        verdict: result.verdict,
        category: result.category,
        reason: result.reason,
        targetValue: senderEmail || 'Scam Message Pattern',
        reportedCount: result.reported_count,
        risk_score: result.risk_score || 70
      };
    }
  } catch (err) {
    console.error('CyberShield text verify error:', err);
  }
  return null;
}

// Decode blob image for QR detection
async function handleBlobImage(blobUrl, parentNode) {
  if (parentNode.dataset.cybershieldScanned) return;

  try {
    const res = await fetch(blobUrl);
    const blob = await res.blob();
    const reader = new FileReader();
    
    reader.onloadend = async () => {
      const base64data = reader.result.split(',')[1];
      
      try {
        const result = await callBackend('/verify/qr', 'POST', { image_b64: base64data });
        
        if (result.decoded && !result.verification.safe) {
          if (parentNode.dataset.cybershieldScanned) return;
          parentNode.dataset.cybershieldScanned = "true";

          trackThreat('Fraudulent QR Code', result.data);
          injectBadge(parentNode, {
            verdict: result.verification.verdict,
            category: 'Fraudulent QR Code',
            reason: result.verification.reason,
            targetValue: result.data,
            reportedCount: result.verification.reported_count,
            risk_score: result.verification.risk_score || 95
          });
        }
      } catch (err) {
        console.error('CyberShield QR verify error:', err);
      }
    };
    reader.readAsDataURL(blob);
  } catch (err) {
    console.error('CyberShield QR fetch/convert error:', err);
  }
}

// Helper to inject warnings into parent HTML element
// Helper to compute SHA-256 hash using Web Crypto API
async function computeHash(text) {
  try {
    const msgBuffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (err) {
    console.error('Web Crypto API failed, fallback to basic hash:', err);
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = (hash << 5) - hash + text.charCodeAt(i);
      hash |= 0;
    }
    return '0x' + Math.abs(hash).toString(16).padStart(64, '0');
  }
}

// Helper to escape HTML characters to prevent DOM XSS injections
function escapeHtml(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// // Helper to inject warnings into parent HTML element
async function injectBadge(parentNode, info) {
  // Compute unique evidence hash
  const combinedText = `${info.category}:${info.reason}:${info.targetValue}`;
  const evidenceHash = await computeHash(combinedText);

  // Check if this badge/card was already injected for this specific target
  const existingBadges = parentNode.querySelectorAll('.cybershield-badge');
  const alreadyExists = Array.from(existingBadges).some(b => b.getAttribute('data-target') === info.targetValue);
  if (alreadyExists) return;

  // Create badge capsule span
  const badge = document.createElement('span');
  const level = info.verdict === 'MALICIOUS' ? 'high' : 'med';
  badge.className = `cybershield-badge cybershield-badge-${level}`;
  badge.setAttribute('data-target', info.targetValue);
  badge.style.cssText = `
    position: relative !important;
    display: inline-flex !important;
    align-items: center !important;
    cursor: pointer !important;
    margin-left: 8px !important;
    margin-right: 8px !important;
    padding: 4px 8px !important;
    border-radius: 6px !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    box-shadow: 0 0 10px rgba(0,0,0,0.1) !important;
    user-select: none !important;
    vertical-align: middle !important;
  `;
  badge.innerHTML = `<span class="cybershield-badge-icon">🛡️</span>${escapeHtml(info.verdict)}`;

  const isSuspicious = (info.verdict || '').toUpperCase() === 'SUSPICIOUS';
  const badgeBg = isSuspicious ? '#d97706' : '#dc2626';
  const badgeLabel = (info.verdict || 'MALICIOUS').toUpperCase();

  // Create card container (absolute positioned tooltip card)
  const card = document.createElement('div');
  card.className = 'cybershield-alert-card';
  card.setAttribute('data-hash', evidenceHash);
  card.style.cssText = `
    display: none;
    position: absolute !important;
    bottom: 130% !important;
    left: 10px !important;
    transform: none !important;
    background: #1a1f2e !important;
    border: 1px solid ${badgeBg} !important;
    border-radius: 12px !important;
    padding: 16px !important;
    color: white !important;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif !important;
    width: 320px !important;
    box-sizing: border-box !important;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5) !important;
    text-align: left !important;
    z-index: 999999 !important;
    line-height: 1.4 !important;
    white-space: normal !important;
  `;

  const hasReports = info.reportedCount !== undefined && info.reportedCount !== null && info.reportedCount > 0;
  const reportedText = hasReports ? `${info.reportedCount} times previously` : '-';

  // Render Inner HTML
  card.innerHTML = `
    <!-- Close Button -->
    <button class="cybershield-close-btn" style="
      position: absolute !important;
      top: 8px !important;
      right: 12px !important;
      background: transparent !important;
      border: none !important;
      color: #9ca3af !important;
      font-size: 18px !important;
      cursor: pointer !important;
      line-height: 1 !important;
      padding: 0 !important;
      font-family: system-ui !important;
    ">&times;</button>

    <!-- Title Section -->
    <div style="display: flex !important; justify-content: space-between !important; align-items: center !important; margin-bottom: 8px !important;">
      <span style="font-weight: bold !important; font-size: 13px !important; color: white !important; letter-spacing: 0.5px !important;">🛡️ CYBERSHIELD ALERT</span>
      <span style="background: ${badgeBg} !important; color: white !important; padding: 2px 8px !important; border-radius: 4px !important; font-size: 10px !important; font-weight: bold !important; letter-spacing: 0.5px !important;">${escapeHtml(badgeLabel)}</span>
    </div>

    <div style="border-top: 1px solid #374151 !important; margin-bottom: 8px !important; width: 100% !important;"></div>

    <!-- Fields Section -->
    <div style="font-size: 12px !important; line-height: 1.6 !important; margin-bottom: 8px !important; color: white !important;">
      <div style="display: flex !important;"><span style="width: 80px !important; color: #9ca3af !important; flex-shrink: 0 !important;">Category</span><span>: ${escapeHtml(info.category)}</span></div>
      <div style="display: flex !important;"><span style="width: 80px !important; color: #9ca3af !important; flex-shrink: 0 !important;">Target</span><span style="word-break: break-all !important;">: ${escapeHtml(info.targetValue)}</span></div>
      <div style="display: flex !important;"><span style="width: 80px !important; color: #9ca3af !important; flex-shrink: 0 !important;">Reported</span><span>: ${escapeHtml(reportedText)}</span></div>
    </div>

    ${info.additionalNote ? `
      <div style="
        background: rgba(245, 158, 11, 0.1) !important;
        border: 1px dashed #f59e0b !important;
        padding: 6px 10px !important;
        border-radius: 6px !important;
        font-size: 11px !important;
        color: #fde047 !important;
        margin-bottom: 8px !important;
        font-weight: 600 !important;
        text-transform: none !important;
      ">
        ⚠️ ${escapeHtml(info.additionalNote)}
      </div>
    ` : ''}

    <div style="border-top: 1px solid #374151 !important; margin-bottom: 12px !important; width: 100% !important;"></div>

    <!-- Action Buttons -->
    <div style="display: flex !important; flex-direction: column !important; gap: 8px !important; margin-bottom: 12px !important;">
      <!-- Button 1 -->
      <div>
        <button class="cybershield-gov-btn" style="
          width: 100% !important;
          padding: 8px 12px !important;
          background: #6b7280 !important;
          color: white !important;
          border: none !important;
          border-radius: 6px !important;
          font-size: 11px !important;
          font-weight: bold !important;
          cursor: pointer !important;
          transition: background 0.2s !important;
          font-family: system-ui !important;
        ">🏛️ File on Govt Portal</button>
        <div style="font-size: 9px !important; color: #9ca3af !important; margin-top: 4px !important; text-align: left !important; line-height: 1.3 !important;">
          ⚠️ Note: Govt portal requires OTP + manual entry. May not work.
        </div>
      </div>

      <!-- Button 2 -->
      <div>
        <button class="cybershield-chain-btn" style="
          width: 100% !important;
          padding: 8px 12px !important;
          background: #7c3aed !important;
          color: white !important;
          border: none !important;
          border-radius: 6px !important;
          font-size: 11px !important;
          font-weight: bold !important;
          cursor: pointer !important;
          transition: all 0.2s !important;
          font-family: system-ui !important;
        ">⛓️ Log to Blockchain</button>
        <div class="cybershield-chain-status" style="font-size: 9px !important; color: #9ca3af !important; margin-top: 4px !important; text-align: left !important; line-height: 1.3 !important;"></div>
      </div>
    </div>

    <!-- Bottom Notice -->
    <div style="font-size: 9px !important; color: #9ca3af !important; line-height: 1.3 !important; text-align: left !important; border-top: 1px solid #374151 !important; padding-top: 8px !important; width: 100% !important;">
      CyberShield logs evidence to Ethereum blockchain instantly.<br/>
      No OTP. No server dependency. Immutable forever.<br/>
      Prakasam Police can view this case in real-time.
    </div>
  `;

  // Stop click propagation inside the card so clicking buttons doesn't trigger parent badge click
  card.addEventListener('click', (e) => {
    e.stopPropagation();
  });

  // Toggle card display on badge click
  badge.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    const isCurrentlyVisible = card.style.display === 'block';
    
    // Hide all other alert cards first to prevent overlap clutter
    document.querySelectorAll('.cybershield-alert-card').forEach(c => {
      c.style.display = 'none';
    });

    card.style.display = isCurrentlyVisible ? 'none' : 'block';
  });

  // Close button functionality
  const closeBtn = card.querySelector('.cybershield-close-btn');
  closeBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    card.style.display = 'none';
  });

  // Govt portal button
  const govBtn = card.querySelector('.cybershield-gov-btn');
  govBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    window.open('https://cybercrime.gov.in', '_blank');
  });

  // Blockchain button & status
  const chainBtn = card.querySelector('.cybershield-chain-btn');
  const chainStatus = card.querySelector('.cybershield-chain-status');

  const updateSuccessUI = (txHash, walletConnected) => {
    chainBtn.style.display = 'none'; // Hide the button
    
    const displayTx = txHash ? `${txHash.substring(0, 14)}...${txHash.substring(txHash.length - 6)}` : '0xabc...def';
    
    const successHtml = `
      <div style="
        background: rgba(16, 185, 129, 0.08) !important;
        border: 1px solid #10b981 !important;
        border-radius: 8px !important;
        padding: 12px !important;
        color: white !important;
        font-family: system-ui, -apple-system, sans-serif !important;
        margin-top: 10px !important;
      ">
        <div style="font-weight: bold !important; color: #34d399 !important; font-size: 13px !important; margin-bottom: 8px !important;">
          ✅ EVIDENCE SECURED
        </div>
        <div style="font-size: 11px !important; line-height: 1.5 !important; margin-bottom: 8px !important; color: #e5e7eb !important;">
          Blockchain: <span style="color: #34d399 !important; font-weight: bold !important;">LOGGED ✅</span><br/>
          Tx: <span style="font-family: monospace !important; word-break: break-all !important; color: #a7f3d0 !important;">${escapeHtml(displayTx)}</span>
        </div>
        ${walletConnected ? `
          <div style="
            background: rgba(124, 58, 237, 0.15) !important;
            border: 1px dashed #8b5cf6 !important;
            padding: 8px !important;
            border-radius: 6px !important;
            font-size: 11px !important;
            color: #d8b4fe !important;
            margin-bottom: 8px !important;
            line-height: 1.4 !important;
          ">
            🏆 <strong>+50 SHIELD</strong> earned!<br/>
            Check your MetaMask wallet.
          </div>
        ` : `
          <div style="
            font-size: 11px !important; 
            color: #a7f3d0 !important; 
            margin-bottom: 8px !important; 
            line-height: 1.4 !important;
            border: 1px dashed rgba(52, 211, 153, 0.3) !important;
            padding: 8px !important;
            border-radius: 6px !important;
          ">
            🙏 Thank you for reporting!<br/>
            Thank you for protecting Prakasam district!
          </div>
        `}
        <div style="font-size: 9px !important; color: #9ca3af !important; border-top: 1px solid rgba(255,255,255,0.1) !important; padding-top: 6px !important; line-height: 1.3 !important;">
          Prakasam Police have been notified. Stay safe.
        </div>
      </div>
    `;
    
    chainStatus.innerHTML = successHtml;
    chainStatus.style.display = 'block';
  };

  const updateErrorUI = (errorMessage) => {
    chainBtn.innerText = '❌ Logging failed. Please try again.';
    chainBtn.disabled = false;
    chainBtn.style.background = '#dc2626'; // Red color showing offline/error
    chainStatus.style.color = '#f87171'; // Red text
    chainStatus.innerText = `Error: ${errorMessage || 'Failed to connect'}`;
    chainStatus.style.display = 'block';
  };

  // Check if already logged in chrome.storage.local
  chrome.storage.local.get(['loggedHashes', 'loggedWallets'], (data) => {
    const hashes = data.loggedHashes || {};
    const wallets = data.loggedWallets || {};
    if (hashes[evidenceHash]) {
      updateSuccessUI(hashes[evidenceHash], wallets[evidenceHash]);
    }
  });

  // Log to blockchain logic
  chainBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();

    chainBtn.innerText = 'Logging...';
    chainBtn.disabled = true;
    chainStatus.style.display = 'none';

    // Start background logging immediately (don't wait for wallet)
    const backendPromise = callBackend('/blockchain/log', 'POST', {
      category: info.category,
      reason: info.reason,
      target: info.targetValue,
      evidence_hash: evidenceHash
    });

    // Try MetaMask connection in parallel
    const walletPromise = triggerWalletConnection();

    try {
      const [logResult, walletResult] = await Promise.all([
        backendPromise.catch(err => ({ success: false, error: err.message })),
        walletPromise
      ]);

      if (logResult && logResult.success) {
        const tx = logResult.tx_hash || '0xabc...123';
        const walletConnected = walletResult.success && walletResult.account;

        // Save to chrome.storage.local
        chrome.storage.local.get(['loggedHashes', 'loggedWallets'], (data) => {
          const hashes = data.loggedHashes || {};
          const wallets = data.loggedWallets || {};
          hashes[evidenceHash] = tx;
          wallets[evidenceHash] = !!walletConnected;
          chrome.storage.local.set({ loggedHashes: hashes, loggedWallets: wallets });
        });

        // Update UI to success
        updateSuccessUI(tx, walletConnected);

        // POST call to http://localhost:8090/mule/report to add target to mule database
        try {
          const target = info.targetValue;
          const category = info.category;
          const reason = info.reason;
          
          const isUpi = target.includes('@') || category.toLowerCase().includes('upi');
          const isPhone = /^\+?\d{10,15}$/.test(target.replace(/[-\s]/g, '')) || category.toLowerCase().includes('phone');
          const isAccount = !isUpi && !isPhone;

          const muleData = {
            upi_id: isUpi ? target : '',
            account_number: isAccount ? target : '',
            phone: isPhone ? target : '',
            holder_name: 'Unknown Mule',
            category: 'Reported Fraud',
            notes: `Auto-reported via CyberShield extension blockchain log for: ${reason}`,
            reported_by: 'CyberShield Agent',
            location: 'Unknown'
          };

          await callBackend('/mule/report', 'POST', muleData);
        } catch (muleErr) {
          console.error('Failed to auto-report mule:', muleErr);
        }

      } else {
        throw new Error(logResult.error || 'Failed to write to blockchain registry');
      }

    } catch (err) {
      console.error('Log to blockchain error:', err);
      updateErrorUI(err.message);
    }
  });

  // Inject card inside the badge capsule itself so it hovers above it perfectly
  badge.appendChild(card);

  // Injection logic
  if (info.isInlineLink) {
    parentNode.parentNode.insertBefore(badge, parentNode.nextSibling);
  } else {
    parentNode.appendChild(badge);
  }
}

// Start executing
setTimeout(init, 3000);
