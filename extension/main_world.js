// CyberShield Main World Bridge
// This script runs in the webpage's MAIN world context to interact with window.ethereum directly.

// Helper to left-pad an address to 32 bytes (64 hex characters)
const padAddress = (addr) => {
  const clean = addr.toLowerCase().replace('0x', '');
  return clean.padStart(64, '0');
};

// Helper to left-pad a hex amount to 32 bytes (64 hex characters)
const padUint256 = (amountHex) => {
  return amountHex.padStart(64, '0');
};

window.addEventListener('message', async (event) => {
  // Only process connection requests sent by the content script
  if (event.data && event.data.type === 'CYBERSHIELD_CONNECT_WALLET') {
    console.log('[CyberShield Main World] Received CYBERSHIELD_CONNECT_WALLET request');
    const hasEthereum = typeof window.ethereum !== 'undefined';
    console.log('[CyberShield Main World] window.ethereum exists:', hasEthereum);
    
    if (!hasEthereum) {
      console.warn('[CyberShield Main World] window.ethereum is undefined. MetaMask is not installed or not active.');
      window.postMessage({ type: 'CYBERSHIELD_WALLET_RESULT', success: false, reason: 'no_metamask' }, '*');
      return;
    }

    try {
      console.log('[CyberShield Main World] Requesting accounts from MetaMask...');
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      console.log('[CyberShield Main World] Accounts connected successfully:', accounts);
      
      try {
        console.log('[CyberShield Main World] Requesting wallet permissions to show account selector...');
        await window.ethereum.request({
          method: 'wallet_requestPermissions',
          params: [{ eth_accounts: {} }]
        });
      } catch (permErr) {
        console.warn('[CyberShield Main World] Permissions request failed or skipped, continuing with current accounts:', permErr.message);
      }

      // Deployed address of ShieldToken.sol contract
      const tokenAddress = '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0';
      const userAddress = accounts[0];
      
      // ABI encode the mint(address,uint256) function call:
      // method id: bytes4(keccak256("mint(address,uint256)")) = 40c10f19
      const methodId = '40c10f19';
      const toParam = padAddress(userAddress);
      const amountParam = padUint256('2b5e3af16b1880000'); // 50 * 10^18 in hex
      const transactionData = '0x' + methodId + toParam + amountParam;

      console.log('[CyberShield Main World] Prompting token reward mint transaction...');
      const txHash = await window.ethereum.request({
        method: 'eth_sendTransaction',
        params: [{
          from: userAddress,
          to: tokenAddress,
          data: transactionData
        }]
      });
      console.log('[CyberShield Main World] Mint transaction successful! Tx Hash:', txHash);

      window.postMessage({ type: 'CYBERSHIELD_WALLET_RESULT', success: true, account: userAddress, txHash }, '*');
    } catch (err) {
      console.error('[CyberShield Main World] MetaMask request rejected or failed:', err);
      window.postMessage({ type: 'CYBERSHIELD_WALLET_RESULT', success: false, reason: 'user_cancel', error: err.message }, '*');
    }
  }
});
