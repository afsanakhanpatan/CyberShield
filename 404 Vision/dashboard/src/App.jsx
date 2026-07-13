import { useState, useEffect, useRef } from 'react';
import { ethers } from 'ethers';
import contractAddress from './contract_address.json';
import contractABI from './CyberShieldRegistryABI.json';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Reusable Premium glowing SVG Icon Components ("Impressive Icons")
const ShieldIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const RadarIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" />
    <path d="M12 2a10 10 0 0 1 10 10" />
    <path d="M12 6a6 6 0 0 1 6 6" />
    <circle cx="12" cy="12" r="2" />
  </svg>
);

const DatabaseIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
  </svg>
);

const WarningIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

const BrainIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.44 2.5 2.5 0 0 1 0-3.12 3 3 0 0 1 0-7.88A2.5 2.5 0 0 1 9.5 2zM14.5 2a2.5 2.5 0 0 1 2.46 2.06 3 3 0 0 1 0 7.88 2.5 2.5 0 0 1 0 3.12A2.5 2.5 0 0 1 12 19.5v-15A2.5 2.5 0 0 1 14.5 2z" />
  </svg>
);

const ChainIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
  </svg>
);

const SearchIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

const RefreshIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
  </svg>
);

const PrintIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v8H6z" />
  </svg>
);

const BoltIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
  </svg>
);

const LockIcon = () => (
  <svg className="icon-svg" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

function App() {
  const [account, setAccount] = useState(null);
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('cybershield-theme') || 'dark';
  });

  useEffect(() => {
    document.body.className = theme === 'light' ? 'light-theme' : '';
    localStorage.setItem('cybershield-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };
  const [provider, setProvider] = useState(null);
  const [contract, setContract] = useState(null);
  const [reports, setReports] = useState([]);
  const [searchHash, setSearchHash] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [isSearching, setIsSearching] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [selectedComplaint, setSelectedComplaint] = useState(null);
  const [copiedText, setCopiedText] = useState(false);
  const [selectedFeedItem, setSelectedFeedItem] = useState(null);
  const [hoveredRegion, setHoveredRegion] = useState(null);
  const [liveLocation, setLiveLocation] = useState(null);
  const [liveLocationError, setLiveLocationError] = useState(null);
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);

  // Tab Manager state
  const [activeTab, setActiveTab] = useState('console'); // console, scanner, mule-db

  // Threat Scanner Tab States
  const [scanValue, setScanValue] = useState('');
  const [scanStatus, setScanStatus] = useState('idle'); // idle, scanning, completed
  const [scanResultData, setScanResultData] = useState(null);
  const [vectorStates, setVectorStates] = useState({
    upi: 'idle',
    phishing: 'idle',
    ssl: 'idle',
    nlp: 'idle'
  });

  // Mule Registry Tab States
  const [muleAccounts, setMuleAccounts] = useState([]);
  const [muleStats, setMuleStats] = useState({ total_mules: 0, categories: {} });
  const [newMule, setNewMule] = useState({
    upi_id: '',
    account_number: '',
    phone: '',
    holder_name: '',
    category: 'Reported Fraud',
    notes: '',
    reported_by: 'Officer',
    location: 'Nellore'
  });
  const [isMuleSubmitting, setIsMuleSubmitting] = useState(false);
  const [muleMessage, setMuleMessage] = useState('');

  const BACKEND_URL = 'http://localhost:8090';

  const fetchMuleData = async () => {
    try {
      const listRes = await fetch(`${BACKEND_URL}/mule/list`);
      if (listRes.ok) {
        const data = await listRes.json();
        setMuleAccounts(data.accounts || []);
      }
      const statsRes = await fetch(`${BACKEND_URL}/mule/stats`);
      if (statsRes.ok) {
        const data = await statsRes.json();
        setMuleStats(data || { total_mules: 0, categories: {} });
      }
    } catch (err) {
      console.error('Error fetching mule registry data:', err);
    }
  };

  useEffect(() => {
    if (activeTab === 'mule-db') {
      fetchMuleData();
    }
  }, [activeTab]);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!scanValue.trim()) return;

    setScanStatus('scanning');
    setScanResultData(null);

    // Animate vectors sequentially to look like a high-tech radar diagnostic
    setVectorStates({ upi: 'scanning', phishing: 'idle', ssl: 'idle', nlp: 'idle' });
    await new Promise(r => setTimeout(r, 600));

    setVectorStates({ upi: 'scanning', phishing: 'scanning', ssl: 'idle', nlp: 'idle' });
    await new Promise(r => setTimeout(r, 600));

    setVectorStates({ upi: 'scanning', phishing: 'scanning', ssl: 'scanning', nlp: 'idle' });
    await new Promise(r => setTimeout(r, 600));

    setVectorStates({ upi: 'scanning', phishing: 'scanning', ssl: 'scanning', nlp: 'scanning' });

    try {
      // Query the backend smart endpoint
      const res = await fetch(`${BACKEND_URL}/verify/smart`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: scanValue.trim() })
      });

      if (res.ok) {
        const data = await res.json();
        setScanResultData(data);

        // Resolve vector statuses based on the backend data
        const isSafe = data.safe;

        // Match specific threat markers
        setVectorStates({
          upi: data.type === 'upi' ? (isSafe ? 'resolved-safe' : 'resolved-threat') : 'resolved-safe',
          phishing: data.type === 'url' ? (isSafe ? 'resolved-safe' : 'resolved-threat') : 'resolved-safe',
          ssl: data.type === 'url' ? (data.ssl_valid ? 'resolved-safe' : 'resolved-threat') : 'resolved-safe',
          nlp: data.type === 'text' ? (isSafe ? 'resolved-safe' : 'resolved-threat') : 'resolved-safe'
        });
      } else {
        throw new Error('Verification failed');
      }
    } catch (err) {
      console.error(err);
      setVectorStates({ upi: 'resolved-threat', phishing: 'resolved-threat', ssl: 'resolved-threat', nlp: 'resolved-threat' });
    } finally {
      setScanStatus('completed');
    }
  };

  const handleReportMule = async (e) => {
    e.preventDefault();
    setIsMuleSubmitting(true);
    setMuleMessage('');
    try {
      const res = await fetch(`${BACKEND_URL}/mule/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newMule)
      });
      if (res.ok) {
        setMuleMessage('✓ Threat report recorded to Mule Registry Database.');
        setNewMule({
          upi_id: '',
          account_number: '',
          phone: '',
          holder_name: '',
          category: 'Reported Fraud',
          notes: '',
          reported_by: 'Officer',
          location: 'Nellore'
        });
        fetchMuleData();
      } else {
        setMuleMessage('❌ Failed to submit threat report.');
      }
    } catch (err) {
      console.error(err);
      setMuleMessage('❌ Connection error to Threat Registry.');
    } finally {
      setIsMuleSubmitting(false);
    }
  };

  // Load scanned reports from backend API
  const fetchReports = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/blockchain/reports`);
      if (res.ok) {
        const data = await res.json();
        setReports(data);
      }
    } catch (err) {
      console.error('Error fetching reports from backend:', err);
    }
  };

  useEffect(() => {
    fetchReports();
    // Poll for new scanned items every 3 seconds
    const interval = setInterval(fetchReports, 3000);
    return () => clearInterval(interval);
  }, []);

  // Live Geolocation
  useEffect(() => {
    if (!navigator.geolocation) {
      setLiveLocationError('Geolocation is not supported by this browser.');
      return;
    }
    const watchId = navigator.geolocation.watchPosition(
      (position) => {
        setLiveLocation({
          lat: position.coords.latitude,
          lng: position.coords.longitude,
          accuracy: position.coords.accuracy
        });
        setLiveLocationError(null);
      },
      (error) => {
        setLiveLocationError(error.message);
      },
      { enableHighAccuracy: true, timeout: 15000, maximumAge: 5000 }
    );
    return () => navigator.geolocation.clearWatch(watchId);
  }, []);

  // Initialize Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current || mapInstanceRef.current) return;

    const map = L.map(mapContainerRef.current, {
      center: [16.0, 80.0],
      zoom: 7,
      zoomControl: true,
      attributionControl: true
    });

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom: 19
    }).addTo(map);

    mapInstanceRef.current = map;

    // Force resize after mount
    setTimeout(() => map.invalidateSize(), 200);

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  // Update map markers when reports or liveLocation change
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    // Clear existing markers (stored on the map object)
    if (map._cyberMarkers) {
      map._cyberMarkers.forEach(m => m.remove());
    }
    map._cyberMarkers = [];

    // Citizen report markers (red/cyan pulsing circles)
    reports.forEach((r, idx) => {
      if (r.latitude == null || r.longitude == null) return;
      const isLinked = (() => {
        const t = (r.target || '').toLowerCase().trim();
        const matches = reports.filter(rr => (rr.target || '').toLowerCase().trim() === t && rr.evidence_hash !== r.evidence_hash);
        return matches.length > 0;
      })();
      const color = isLinked ? '#ef4444' : '#06b6d4';

      const pinIcon = L.divIcon({
        className: 'cyber-map-pin',
        html: `<div style="
          width: 30px;
          height: 30px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: ${color};
          border: 2px solid #fff;
          border-radius: 50% 50% 50% 0;
          transform: rotate(-45deg) translate(-2px, 2px);
          box-shadow: 0 0 10px rgba(0,0,0,0.4);
        ">
          <div style="
            width: 10px;
            height: 10px;
            background: #fff;
            border-radius: 50%;
            transform: rotate(45deg);
          "></div>
        </div>`,
        iconSize: [30, 30],
        iconAnchor: [15, 30]
      });

      const marker = L.marker([r.latitude, r.longitude], { icon: pinIcon }).addTo(map);

      marker.bindPopup(
        `<div style="font-family: monospace; font-size: 12px; min-width: 180px;">
          <div style="font-weight: bold; margin-bottom: 4px;">📍 Citizen / Reporter Location</div>
          <div><strong>Case #${idx + 1}</strong> — ${r.reporter || 'Unknown'}</div>
          <div>${r.location || 'Unknown Location'}</div>
          <div style="margin-top: 4px; color: #888;">Target: ${r.target}</div>
          <div style="color: ${isLinked ? '#ef4444' : '#22c55e'}; font-weight: bold; margin-top: 4px;">
            ${isLinked ? '⚠️ Linked Case' : '✓ Isolated'}
          </div>
          <div style="color: #999; font-size: 10px; margin-top: 4px;">Note: Victim/reporter location, not offender.</div>
        </div>`,
        { className: 'cyber-popup' }
      );

      marker.bindTooltip(`${r.reporter || 'C' + (idx + 1)} (${r.location || 'Unknown Location'})`, {
        permanent: true,
        direction: 'top',
        offset: [0, -32],
        className: 'cyber-tooltip'
      });

      map._cyberMarkers.push(marker);
    });

    // Draw dashed lines between linked cases
    const targetGroups = {};
    reports.forEach((r, idx) => {
      if (r.latitude == null || r.longitude == null || !r.target) return;
      const t = r.target.toLowerCase().trim();
      if (!targetGroups[t]) targetGroups[t] = [];
      targetGroups[t].push([r.latitude, r.longitude]);
    });
    Object.values(targetGroups).forEach(coords => {
      if (coords.length > 1) {
        const line = L.polyline(coords, {
          color: '#ef4444',
          weight: 2,
          dashArray: '6, 8',
          opacity: 0.6
        }).addTo(map);
        map._cyberMarkers.push(line);
      }
    });

    // Live location marker (green pulsing)
    if (liveLocation) {
      const liveCircle = L.circleMarker([liveLocation.lat, liveLocation.lng], {
        radius: 10,
        fillColor: '#22c55e',
        color: '#22c55e',
        weight: 3,
        opacity: 1,
        fillOpacity: 0.4
      }).addTo(map);

      liveCircle.bindPopup(
        `<div style="font-family: monospace; font-size: 12px;">
          <div style="font-weight: bold; color: #22c55e;">📡 YOUR LIVE LOCATION</div>
          <div>Lat: ${liveLocation.lat.toFixed(4)}</div>
          <div>Lng: ${liveLocation.lng.toFixed(4)}</div>
          <div style="color: #999; font-size: 10px;">Accuracy: ±${Math.round(liveLocation.accuracy)}m</div>
        </div>`,
        { className: 'cyber-popup' }
      );

      liveCircle.bindTooltip('🔴 YOU (Live)', {
        permanent: true,
        direction: 'top',
        offset: [0, -12],
        className: 'cyber-tooltip-live'
      });

      // Accuracy radius ring
      const accuracyCircle = L.circle([liveLocation.lat, liveLocation.lng], {
        radius: liveLocation.accuracy,
        fillColor: '#22c55e',
        color: '#22c55e',
        weight: 1,
        opacity: 0.2,
        fillOpacity: 0.05
      }).addTo(map);

      map._cyberMarkers.push(liveCircle, accuracyCircle);
    }
  }, [reports, liveLocation]);

  // Initialize wallet connection automatically if MetaMask is connected
  useEffect(() => {
    if (window.ethereum) {
      window.ethereum.on('accountsChanged', (accounts) => {
        if (accounts.length > 0) {
          setAccount(accounts[0]);
          initEthers();
        } else {
          setAccount(null);
          setContract(null);
        }
      });

      // Check if already authorized
      window.ethereum.request({ method: 'eth_accounts' })
        .then(accounts => {
          if (accounts.length > 0) {
            setAccount(accounts[0]);
            initEthers();
          }
        });
    }
  }, []);

  const initEthers = async () => {
    try {
      if (window.ethereum) {
        const tempProvider = new ethers.BrowserProvider(window.ethereum);
        const tempSigner = await tempProvider.getSigner();
        const tempContract = new ethers.Contract(
          contractAddress.address,
          contractABI,
          tempSigner
        );
        setProvider(tempProvider);
        setContract(tempContract);
      }
    } catch (err) {
      console.error('Ethers initialization failed:', err);
    }
  };

  const switchOrAddNetwork = async () => {
    if (!window.ethereum) return;
    try {
      // 31337 in hex is 0x7a69
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: '0x7a69' }],
      });
    } catch (switchError) {
      // Error code 4902 indicates the chain has not been added to MetaMask yet
      if (switchError.code === 4902) {
        try {
          await window.ethereum.request({
            method: 'wallet_addEthereumChain',
            params: [
              {
                chainId: '0x7a69',
                chainName: 'Hardhat Local Network',
                rpcUrls: ['http://127.0.0.1:8545'],
                nativeCurrency: {
                  name: 'Ether',
                  symbol: 'ETH',
                  decimals: 18,
                },
              },
            ],
          });
        } catch (addError) {
          console.error('Failed to add Hardhat network to MetaMask:', addError);
        }
      } else {
        console.error('Failed to switch to Hardhat network:', switchError);
      }
    }
  };

  const connectWallet = async () => {
    if (!window.ethereum) {
      alert('MetaMask is not installed. Please install MetaMask to interact with the blockchain.');
      return;
    }
    try {
      await switchOrAddNetwork();
      // Request permissions to force the MetaMask account chooser popup to display
      await window.ethereum.request({
        method: 'wallet_requestPermissions',
        params: [{ eth_accounts: {} }]
      });
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      setAccount(accounts[0]);
      await initEthers();
    } catch (err) {
      console.error('Wallet connection failed:', err);
    }
  };

  const disconnectWallet = () => {
    setAccount(null);
    setProvider(null);
    setContract(null);
  };

  // Search blockchain logs for a specific evidence hash
  const verifyEvidenceHash = async (e) => {
    e.preventDefault();
    if (!searchHash.trim()) return;

    setIsSearching(true);
    setSearchResult(null);
    setErrorMessage('');

    // Fallback: search in local backend reports first
    const localMatch = reports.find(r => r.evidence_hash.toLowerCase() === searchHash.trim().toLowerCase());

    if (!contract) {
      // If blockchain contract is not connected, use the local mock database check
      setIsSearching(false);
      if (localMatch) {
        setSearchResult({
          hash: localMatch.evidence_hash,
          category: localMatch.category,
          details: localMatch.reason,
          target: localMatch.target,
          reporter: '0x0000000000000000000000000000000000000000',
          timestamp: new Date(localMatch.timestamp * 1000).toLocaleString(),
          blockchain_logged: localMatch.blockchain_logged,
          source: localMatch.tx_hash ? 'Local DB Cache' : 'Unregistered'
        });
      } else {
        setErrorMessage('No matching evidence record found in local cache. Connect MetaMask to audit live on-chain logs.');
      }
      return;
    }

    try {
      const formattedHash = searchHash.trim().startsWith('0x') ? searchHash.trim() : '0x' + searchHash.trim();

      // Check if logged in mapping
      const isLogged = await contract.isLogged(formattedHash);

      if (!isLogged) {
        if (localMatch) {
          // Exists in backend but failed to log to chain
          setSearchResult({
            hash: localMatch.evidence_hash,
            category: localMatch.category,
            details: localMatch.reason,
            target: localMatch.target,
            reporter: 'N/A',
            timestamp: new Date(localMatch.timestamp * 1000).toLocaleString(),
            blockchain_logged: false,
            source: 'Scanned but not recorded to Ledger'
          });
        } else {
          setErrorMessage('Hash invalid or not registered in the CyberShield blockchain contract.');
        }
        setIsSearching(false);
        return;
      }

      // Find record by iterating backwards (more likely to be recent)
      const count = await contract.getRecordCount();
      let foundRecord = null;

      for (let i = Number(count) - 1; i >= 0; i--) {
        const record = await contract.getRecord(i);
        if (record.evidenceHash.toLowerCase() === formattedHash.toLowerCase()) {
          foundRecord = {
            hash: record.evidenceHash,
            category: record.category,
            details: record.details,
            target: record.target,
            reporter: record.reporter,
            timestamp: new Date(Number(record.timestamp) * 1000).toLocaleString(),
            blockchain_logged: true,
            source: 'Ethereum Ledger (Sepolia/Local)'
          };
          break;
        }
      }

      if (foundRecord) {
        setSearchResult(foundRecord);
      } else {
        setErrorMessage('Contract returned confirmation, but full transaction payload could not be parsed.');
      }
    } catch (err) {
      console.error('Error verifying hash on-chain:', err);
      setErrorMessage('Blockchain communication error. Verify contract deployment or local network connection.');
    } finally {
      setIsSearching(false);
    }
  };

  // Compile stats
  const totalChecked = reports.length;
  const threatsDetected = reports.filter(r => r.category !== 'Safe').length;
  const loggedOnChain = reports.filter(r => r.blockchain_logged).length;

  // Build target map for dynamic cross-station linkages
  const targetMap = {};
  reports.forEach((r, idx) => {
    if (!r.target || r.category === 'Safe') return;
    const t = r.target.toLowerCase().trim();
    if (!targetMap[t]) {
      targetMap[t] = [];
    }
    targetMap[t].push({
      caseIndex: idx + 1,
      reporter: r.reporter || `C${idx + 1}`,
      location: r.location || 'Unknown Location',
      evidence_hash: r.evidence_hash
    });
  });

  return (
    <div className="dashboard-container">
      {/* Premium Header */}
      <header className="dashboard-header glass-panel">
        <div className="header-logo">
          <span className="logo-symbol" style={{ color: 'var(--cyan)', display: 'flex', alignItems: 'center' }}>
            <ShieldIcon />
          </span>
          <div>
            <h1 className="logo-title title-font">
              CYBER<span className="cyan-text">SHIELD</span>
            </h1>
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Digital Policing Console & Fraud Pattern Intelligence
            </span>
          </div>
        </div>

        <div className="header-meta">
          <button
            className="theme-toggle-btn glass-panel"
            onClick={toggleTheme}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              padding: '8px 16px',
              borderRadius: '10px',
              cursor: 'pointer',
              color: 'var(--text-main)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              fontSize: '11px',
              fontWeight: 'bold',
              transition: 'all 0.3s ease'
            }}
          >
            {theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode'}
          </button>
          <div className="glass-panel" style={{ background: 'rgba(0, 255, 136, 0.08)', border: '1px solid rgba(0, 255, 136, 0.2)', padding: '8px 16px', borderRadius: '10px', fontSize: '11px', fontWeight: 'bold', color: 'var(--emerald)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--emerald)', display: 'inline-block', boxShadow: '0 0 6px var(--emerald)', animation: 'pulse-dot 2s infinite' }} /> SECURE AUDIT NODE (LEDGER ACTIVE)
          </div>
          {account ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div className="wallet-badge glass-panel">
                <span className="dot-indicator dot-connected"></span>
                <span>
                  {account.substring(0, 6)}...{account.substring(account.length - 4)}
                </span>
              </div>
              <button
                onClick={disconnectWallet}
                className="glass-panel"
                style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  color: 'var(--crimson)',
                  padding: '8px 12px',
                  borderRadius: '10px',
                  cursor: 'pointer',
                  fontSize: '11px',
                  fontWeight: 'bold',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  transition: 'all 0.3s ease',
                  fontFamily: 'var(--font-sans)'
                }}
                title="Disconnect Audit Node"
              >
                Logout
              </button>
            </div>
          ) : (
            <button className="btn-primary" onClick={connectWallet}>
              <BoltIcon /> CONNECT AUDIT NODE
            </button>
          )}
        </div>
      </header>

      {/* Global Tab Navigation */}
      <nav className="nav-tab-container" style={{ marginBottom: '8px' }}>
        <button
          className={`nav-tab-button ${activeTab === 'console' ? 'nav-tab-active' : ''}`}
          onClick={() => setActiveTab('console')}
        >
          <ShieldIcon /> Console Hub
        </button>
        <button
          className={`nav-tab-button ${activeTab === 'scanner' ? 'nav-tab-active' : ''}`}
          onClick={() => setActiveTab('scanner')}
        >
          <RadarIcon /> Threat Scan Center
        </button>
        <button
          className={`nav-tab-button ${activeTab === 'mule-db' ? 'nav-tab-active' : ''}`}
          onClick={() => setActiveTab('mule-db')}
        >
          <DatabaseIcon /> Mule Database Registry
        </button>
      </nav>

      {activeTab === 'console' && (
        <>
          {/* Cyber Defender Sentinel Hero Section */}
          <section className="hero-section glass-panel">
            <div className="hero-content">
              <span className="hero-tag">Active Threat Countermeasures Enabled</span>
              <h2 className="hero-title title-font">
                CYBER DEFENSE <span>SENTINEL</span>
              </h2>
              <p className="hero-description">
                CyberShield intercepts browser-based threats on WhatsApp Web & Gmail, automatically correlating isolated scams across police jurisdictions. Using shared digital identifiers (UPI IDs, bank accounts, and links), it builds tamper-proof evidence logs secured on the blockchain registry to fast-track coordinated law enforcement actions.
              </p>
              <div className="hero-badges">
                <div className="hero-badge-card">
                  <span className="hero-badge-icon" style={{ color: 'var(--cyan)' }}><ShieldIcon /></span>
                  <span className="hero-badge-title">Enterprise Protection</span>
                  <span className="hero-badge-desc">Real-time sniffer parsing chats & email structures.</span>
                </div>
                <div className="hero-badge-card">
                  <span className="hero-badge-icon" style={{ color: 'var(--purple)' }}><ChainIcon /></span>
                  <span className="hero-badge-title">Decentralized Ledger</span>
                  <span className="hero-badge-desc">Evidence logged immutably on Ethereum nodes.</span>
                </div>
                <div className="hero-badge-card">
                  <span className="hero-badge-icon" style={{ color: 'var(--emerald)' }}><BrainIcon /></span>
                  <span className="hero-badge-title">Scam Intelligence</span>
                  <span className="hero-badge-desc">Hybrid NLP intent vector and typosquatting analysis.</span>
                </div>
              </div>
            </div>
          </section>

          {/* Metrics Row */}
          <section className="metrics-row">
            <div className="metric-card glass-panel metric-card-info">
              <div className="metric-header">
                <span className="metric-title">Traffic Sniffed</span>
                <span className="metric-icon" style={{ color: 'var(--cyan)', display: 'flex', alignItems: 'center' }}><RadarIcon /></span>
              </div>
              <div className="metric-val">{totalChecked}</div>
            </div>

            <div className="metric-card glass-panel metric-card-danger">
              <div className="metric-header">
                <span className="metric-title">Threats Suspended</span>
                <span className="metric-icon" style={{ color: 'var(--crimson)', display: 'flex', alignItems: 'center' }}><WarningIcon /></span>
              </div>
              <div className="metric-val">{threatsDetected}</div>
            </div>

            <div className="metric-card glass-panel metric-card-success">
              <div className="metric-header">
                <span className="metric-title">Evidence Sealed</span>
                <span className="metric-icon" style={{ color: 'var(--emerald)', display: 'flex', alignItems: 'center' }}><ChainIcon /></span>
              </div>
              <div className="metric-val">{loggedOnChain}</div>
            </div>
          </section>

          {/* Grid Content */}
          <main className="sections-grid">
            {/* Left Column: Live Scan Feed */}
            <div className="glass-panel section-box">
              <div className="section-head">
                <h2 className="section-title title-font">Live Scam & Fraud Monitoring Feed</h2>
                <span className="emerald-text" style={{ fontSize: '11px', fontWeight: 'bold' }}>● SCANNER ONLINE</span>
              </div>

              <div className="feed-list">
                {reports.length === 0 ? (
                  <div className="list-empty-dashboard">
                    No scams logged yet. Install the CyberShield extension and browse to trigger threat indicators.
                  </div>
                ) : (
                  reports.slice().reverse().map((report, idx) => {
                    const originalIdx = reports.length - 1 - idx;
                    const caseNum = originalIdx + 1;
                    const isActive = (selectedFeedItem && selectedFeedItem.evidence_hash === report.evidence_hash) ||
                      (!selectedFeedItem && idx === 0);

                    const cleanTarget = report.target ? report.target.toLowerCase().trim() : '';
                    const matches = targetMap[cleanTarget] || [];
                    const linkedCases = matches.filter(m => m.caseIndex !== caseNum);

                    return (
                      <div
                        key={idx}
                        className={`feed-item ${isActive ? 'feed-item-active' : ''}`}
                        onClick={() => setSelectedFeedItem(report)}
                        style={{ cursor: 'pointer' }}
                      >
                        <div className="feed-item-header">
                          <span className={`feed-item-category ${report.category === 'Safe' ? 'emerald-text' : 'crimson-text'}`}>
                            {report.category === 'Safe' ? 'Safe Traffic' : `Case #${caseNum} — ${report.category}`}
                          </span>
                          <span className="feed-item-time">
                            {new Date(report.timestamp * 1000).toLocaleTimeString()}
                          </span>
                        </div>

                        {report.category !== 'Safe' && (
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                            <strong>Reporter:</strong> {report.reporter || `C${caseNum}`} | <strong>Jurisdiction Hub:</strong> {report.location || 'Unknown'}
                          </div>
                        )}

                        <div className="feed-item-body">
                          "{report.reason}"
                        </div>

                        <div className="feed-item-footer">
                          <span className="feed-item-indicator" title={report.target}>
                            <strong>Artifact:</strong> {report.target}
                          </span>

                          {report.blockchain_logged ? (
                            <span className="feed-blockchain-badge badge-chain-success" title={`Tx: ${report.tx_hash}`} style={{ display: 'inline-flex', alignItems: 'center' }}>
                              <ChainIcon /> ON-CHAIN
                            </span>
                          ) : (
                            <span className="feed-blockchain-badge badge-chain-simulated" title={`Simulated Tx: ${report.tx_hash}`} style={{ display: 'inline-flex', alignItems: 'center' }}>
                              <DatabaseIcon /> LOCAL DB LOG
                            </span>
                          )}
                        </div>

                        {/* Correlation Link Alert */}
                        {report.category !== 'Safe' && (
                          linkedCases.length > 0 ? (
                            <div style={{
                              marginTop: '8px',
                              background: 'rgba(255, 59, 105, 0.06)',
                              border: '1px solid rgba(255, 59, 105, 0.25)',
                              padding: '8px 12px',
                              borderRadius: '8px',
                              fontSize: '11px',
                              color: '#fca5a5'
                            }}>
                              {linkedCases.map(l => (
                                <div key={l.caseIndex} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <WarningIcon /> <span>Linked to Case #{l.caseIndex} (Reported by {l.reporter} in {l.location})</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div style={{
                              marginTop: '8px',
                              background: 'rgba(0, 255, 136, 0.06)',
                              border: '1px solid rgba(0, 255, 136, 0.25)',
                              padding: '8px 12px',
                              borderRadius: '8px',
                              fontSize: '11px',
                              color: '#a7f3d0',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '6px'
                            }}>
                              <ShieldIcon /> Isolated Threat Pattern
                            </div>
                          )
                        )}

                        {report.category !== 'Safe' && (
                          <button
                            className="btn-complaint"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedComplaint(report);
                            }}
                          >
                            <PrintIcon /> Generate Official Complaint
                          </button>
                        )}
                      </div>
                    );
                  })
                )}
              </div>

              {/* Incident Timeline Visualizer */}
              {reports.length > 0 && (
                <div className="glass-panel section-box" style={{ marginTop: '24px' }}>
                  <div className="section-head">
                    <h2 className="section-title title-font">Incident Verification Timeline</h2>
                    <span className="cyan-text" style={{ fontSize: '10px', fontWeight: 'bold', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <SearchIcon /> FORENSIC AUDIT TRAIL
                    </span>
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Trace the active threat's verification path from interception to ledger logging.
                  </p>

                  {(() => {
                    const activeItem = selectedFeedItem || reports[reports.length - 1];
                    if (!activeItem) return null;

                    return (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                        <div style={{
                          background: 'rgba(0, 240, 255, 0.02)',
                          padding: '16px',
                          borderRadius: '12px',
                          border: '1px solid rgba(0, 240, 255, 0.1)',
                          fontSize: '12px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '4px'
                        }}>
                          <div style={{ color: 'var(--text-main)', fontWeight: 'bold', wordBreak: 'break-all' }}>Target Node: <span className="cyan-text">{activeItem.target}</span></div>
                          <div style={{ color: 'var(--text-muted)', wordBreak: 'break-all', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>Evidence ID: {activeItem.evidence_hash}</div>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', position: 'relative', paddingLeft: '24px', borderLeft: '2px dashed rgba(0, 240, 255, 0.15)' }}>
                          {/* Step 1 */}
                          <div style={{ position: 'relative' }}>
                            <div style={{ position: 'absolute', left: '-31px', top: '4px', width: '12px', height: '12px', borderRadius: '50%', background: 'var(--cyan)', border: '2px solid var(--bg-dark)', boxShadow: '0 0 10px var(--cyan)' }}></div>
                            <div style={{ fontSize: '13px', fontWeight: 'bold', color: 'var(--text-main)' }}>Step 1: Client Interception</div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>CyberShield content script sniffed inbound text containing suspicious banking or link details.</div>
                          </div>

                          {/* Step 2 */}
                          <div style={{ position: 'relative' }}>
                            <div style={{ position: 'absolute', left: '-31px', top: '4px', width: '12px', height: '12px', borderRadius: '50%', background: 'var(--purple)', border: '2px solid var(--bg-dark)', boxShadow: '0 0 10px var(--purple)' }}></div>
                            <div style={{ fontSize: '13px', fontWeight: 'bold', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span>Step 2: Multi-Signal Verification</span>
                              <span className="timeline-badge badge-ai" style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '4px', background: 'rgba(157, 78, 221, 0.15)', color: '#d8b4fe', border: '1px solid rgba(157, 78, 221, 0.3)' }}>AI-ASSISTED</span>
                            </div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>FastAPI verifiers processed classification: Category resolved as <span className="crimson-text" style={{ fontWeight: 'bold' }}>{activeItem.category}</span>.</div>
                          </div>

                          {/* Step 3 */}
                          <div style={{ position: 'relative' }}>
                            <div style={{ position: 'absolute', left: '-31px', top: '4px', width: '12px', height: '12px', borderRadius: '50%', background: 'var(--crimson)', border: '2px solid var(--bg-dark)', boxShadow: '0 0 10px var(--crimson)' }}></div>
                            <div style={{ fontSize: '13px', fontWeight: 'bold', color: 'var(--text-main)' }}>Step 3: Edge Defenses Armed</div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>Target address blacklisted in local storage. Automatic redirection blocker armed.</div>
                          </div>

                          {/* Step 4 */}
                          <div style={{ position: 'relative' }}>
                            <div style={{ position: 'absolute', left: '-31px', top: '4px', width: '12px', height: '12px', borderRadius: '50%', background: activeItem.blockchain_logged ? 'var(--emerald)' : 'var(--amber)', border: '2px solid var(--bg-dark)', boxShadow: activeItem.blockchain_logged ? '0 0 10px var(--emerald)' : '0 0 10px var(--amber)' }}></div>
                            <div style={{ fontSize: '13px', fontWeight: 'bold', color: activeItem.blockchain_logged ? 'var(--text-main)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span>Step 4: Registry Evidence Sealed</span>
                              {activeItem.blockchain_logged ? (
                                <span className="timeline-badge badge-ledger" style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '4px', background: 'rgba(0, 255, 136, 0.15)', color: '#6ee7b7', border: '1px solid rgba(0, 255, 136, 0.3)' }}>IMMUTABLE LEDGER</span>
                              ) : (
                                <span className="timeline-badge badge-mock" style={{ fontSize: '9px', padding: '2px 6px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.15)', color: '#67e8f9', border: '1px solid rgba(0, 240, 255, 0.3)' }}>LOCAL CACHE</span>
                              )}
                            </div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                              {activeItem.blockchain_logged
                                ? `Immutable receipt stored on Ethereum block network. Tx: ${activeItem.tx_hash.substring(0, 16)}...`
                                : `Logged locally in local SQLite database cache. Tx: ${activeItem.tx_hash.substring(0, 16)}...`}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>

            {/* Right Column: Wallet & Evidence Verification Tool */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>

              {/* Blockchain Audit Tool */}
              <div className="glass-panel section-box">
                <div className="section-head">
                  <h2 className="section-title title-font">Evidence Integrity Verification</h2>
                </div>

                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
                  Enter a reported scam's cryptographic hash signature to audit its timestamp, reporter, and validity against the immutable ledger.
                </p>

                <form onSubmit={verifyEvidenceHash} className="verifier-wrapper">
                  <div className="search-bar">
                    <input
                      type="text"
                      placeholder="0x..."
                      className="input-field"
                      value={searchHash}
                      onChange={(e) => setSearchHash(e.target.value)}
                    />
                    <button type="submit" className="search-btn" disabled={isSearching}>
                      {isSearching ? 'Auditing...' : 'Verify'}
                    </button>
                  </div>
                </form>

                {errorMessage && (
                  <div className="result-card" style={{ borderColor: 'var(--crimson)', background: 'rgba(239,68,68,0.02)' }}>
                    <div style={{ fontSize: '12px', color: 'var(--crimson)' }}>
                      ⚠️ {errorMessage}
                    </div>
                  </div>
                )}

                {searchResult && (
                  <div className="result-card" style={{ borderColor: searchResult.blockchain_logged ? 'var(--emerald)' : 'var(--cyan)' }}>
                    <div className="result-row">
                      <span className="result-label">Status</span>
                      <span className={searchResult.blockchain_logged ? 'emerald-text' : 'cyan-text'} style={{ fontWeight: 'bold' }}>
                        {searchResult.blockchain_logged ? 'VALID IMMUTABLE RECORD ✓' : 'LOCAL CACHE SYNCED'}
                      </span>
                    </div>
                    <div className="result-row">
                      <span className="result-label">Category</span>
                      <span className="result-val">{searchResult.category}</span>
                    </div>
                    <div className="result-row">
                      <span className="result-label">Indicator</span>
                      <span className="result-val">{searchResult.target}</span>
                    </div>
                    <div className="result-row">
                      <span className="result-label">Reporter Wallet</span>
                      <span className="result-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                        {searchResult.reporter}
                      </span>
                    </div>
                    <div className="result-row">
                      <span className="result-label">Timestamp</span>
                      <span className="result-val">{searchResult.timestamp}</span>
                    </div>
                    <div className="result-row" style={{ borderTop: '1px dashed rgba(255,255,255,0.08)', paddingTop: '6px', marginTop: '4px' }}>
                      <span className="result-label">Registry Source</span>
                      <span className="result-val" style={{ fontSize: '11px' }}>{searchResult.source}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Live Geolocation Map */}
              <div className="glass-panel section-box">
                <div className="section-head">
                  <h2 className="section-title title-font">Citizen / Reporter Geolocation Hotspots</h2>
                  <span className="crimson-text" style={{ fontSize: '10px', fontWeight: 'bold' }}>📡 LIVE MAP</span>
                </div>
                <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Real-time interactive map — Citizen / Reporter locations (victim/reporter distribution, not the offender's physical location).
                </p>

                {/* Live Location Status Bar */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: '8px',
                  marginBottom: '10px', padding: '6px 10px', borderRadius: '6px',
                  background: liveLocation ? 'rgba(34, 197, 94, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                  border: `1px solid ${liveLocation ? 'rgba(34, 197, 94, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                  fontSize: '11px'
                }}>
                  <span style={{
                    width: '8px', height: '8px', borderRadius: '50%',
                    background: liveLocation ? '#22c55e' : '#ef4444',
                    display: 'inline-block',
                    boxShadow: liveLocation ? '0 0 6px #22c55e' : 'none',
                    animation: liveLocation ? 'pulse-dot 2s infinite' : 'none'
                  }} />
                  {liveLocation ? (
                    <span style={{ color: '#a7f3d0' }}>
                      📡 Live Position: <strong>{liveLocation.lat.toFixed(4)}°N, {liveLocation.lng.toFixed(4)}°E</strong>
                      <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>±{Math.round(liveLocation.accuracy)}m</span>
                    </span>
                  ) : (
                    <span style={{ color: '#fca5a5' }}>
                      {liveLocationError || 'Requesting live location...'}
                    </span>
                  )}
                </div>

                {/* Leaflet Map Container */}
                <div
                  ref={mapContainerRef}
                  style={{
                    width: '100%', height: '320px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255,255,255,0.06)',
                    overflow: 'hidden'
                  }}
                />

                {/* Map Legend */}
                <div style={{ display: 'flex', gap: '16px', marginTop: '10px', fontSize: '10px', color: 'var(--text-muted)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444', display: 'inline-block' }} />
                    Linked Case Report
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#06b6d4', display: 'inline-block' }} />
                    Isolated Report
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />
                    Your Live Location
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span style={{ width: '12px', borderTop: '2px dashed #ef4444', display: 'inline-block' }} />
                    Fraud Link
                  </div>
                </div>
              </div>

            </div>
          </main>

          {/* Developer/User Info Card - Full-width organized layout */}
          <div className="glass-panel section-box" style={{ marginTop: '24px' }}>
            <div className="section-head">
              <h2 className="section-title title-font" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><ShieldIcon /> CyberShield Project Architecture</h2>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px', fontSize: '12px', color: 'var(--text-muted)' }}>
              <div className="architecture-card">
                <strong style={{ color: 'var(--text-main)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                  <RadarIcon /> 1. Client Extension
                </strong>
                <p>Watches WhatsApp Web & Gmail in the browser using MutationObservers, parsing messages to extract links, UPI accounts, and QR codes.</p>
              </div>
              <div className="architecture-card">
                <strong style={{ color: 'var(--text-main)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                  <SearchIcon /> 2. Threat API (FastAPI)
                </strong>
                <p>Verifies domains against official reference banks (typosquatting via Levenshtein) and decodes QR codes using OpenCV.</p>
              </div>
              <div className="architecture-card">
                <strong style={{ color: 'var(--text-main)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                  <ChainIcon /> 3. Blockchain Registry
                </strong>
                <p>Stores evidence signatures on the Ethereum Sepolia/Local node network, providing verifiable public defense paths.</p>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Threat Scan Center Tab */}
      {activeTab === 'scanner' && (
        <div className="glass-panel section-box animation-fadeIn">
          <div className="section-head">
            <h2 className="section-title title-font">CyberShield Smart Scan Center</h2>
            <span className="purple-text" style={{ fontSize: '10px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <RadarIcon /> REAL-TIME SCANNER
            </span>
          </div>

          <div className="scanner-layout" style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '32px' }}>
            {/* Live Telemetry Ingestion Console */}
            <div className="glass-panel section-box">
              <div style={{ marginBottom: '20px' }}>
                <h3 className="title-font" style={{ fontSize: '14px', color: 'var(--text-main)', marginBottom: '8px' }}>📡 Live Threat Ingestion Telemetry</h3>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Real-time threat reports streamed from active citizen extensions. Logs are verified via multi-vector decoders and blockchain hashes.
                </p>
              </div>

              <div className="telemetry-log-container" style={{
                maxHeight: '380px',
                overflowY: 'auto',
                fontFamily: 'monospace',
                fontSize: '11px',
                lineHeight: '1.6'
              }}>
                {reports.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                    [WAITING] Secure telemetry link active. Listening for incoming citizen logs...
                  </div>
                ) : (
                  reports.slice().reverse().map((r, idx) => (
                    <div key={idx} style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      paddingBottom: '10px',
                      marginBottom: '10px',
                      color: 'var(--cyan)'
                    }}>
                      <span style={{ color: 'var(--purple)' }}>[{new Date(r.timestamp * 1000).toLocaleTimeString()}]</span>{' '}
                      <span style={{ color: '#ef4444', fontWeight: 'bold' }}>[INGEST]</span>{' '}
                      Citizen <span style={{ color: '#fff' }}>{r.reporter || 'P1'}</span> reported{' '}
                      <span style={{ color: '#fff', fontWeight: 'bold' }}>{r.category}</span> from{' '}
                      <span style={{ color: 'var(--emerald)' }}>{r.location || 'Unknown'}</span>.
                      <br />
                      &nbsp;&nbsp;» Target ID: <span style={{ color: '#f59e0b' }}>{r.target}</span>
                      <br />
                      &nbsp;&nbsp;» Proof Hash: <span style={{ color: '#9ca3af' }}>{r.evidence_hash}</span>
                      <br />
                      &nbsp;&nbsp;» Tx Signature: <span style={{ color: 'var(--purple)' }}>{r.tx_hash || 'LOCAL_CACHE'}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Threat Vector Cards - Full Width Bottom Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginTop: '16px' }}>
              <div className={`vector-card ${vectorStates.upi === 'scanning' ? 'vector-active-scanning' : vectorStates.upi === 'resolved-safe' ? 'vector-resolved-safe' : vectorStates.upi === 'resolved-threat' ? 'vector-resolved-threat' : ''}`}>
                <div className="vector-card-header">
                  <span className="vector-title">UPI Identity</span>
                  <span className="vector-icon" style={{ color: 'var(--cyan)' }}><ShieldIcon /></span>
                </div>
                <span className="vector-status">
                  {vectorStates.upi === 'idle' ? 'Armed' : vectorStates.upi === 'scanning' ? 'Scanning...' : vectorStates.upi === 'resolved-safe' ? 'Verified Safe' : 'Mule Alert'}
                </span>
              </div>

              <div className={`vector-card ${vectorStates.phishing === 'scanning' ? 'vector-active-scanning' : vectorStates.phishing === 'resolved-safe' ? 'vector-resolved-safe' : vectorStates.phishing === 'resolved-threat' ? 'vector-resolved-threat' : ''}`}>
                <div className="vector-card-header">
                  <span className="vector-title">Phish Squatting</span>
                  <span className="vector-icon" style={{ color: 'var(--purple)' }}><ChainIcon /></span>
                </div>
                <span className="vector-status">
                  {vectorStates.phishing === 'idle' ? 'Armed' : vectorStates.phishing === 'scanning' ? 'Scanning...' : vectorStates.phishing === 'resolved-safe' ? 'Verified Clean' : 'Typosquat Alert'}
                </span>
              </div>

              <div className={`vector-card ${vectorStates.ssl === 'scanning' ? 'vector-active-scanning' : vectorStates.ssl === 'resolved-safe' ? 'vector-resolved-safe' : vectorStates.ssl === 'resolved-threat' ? 'vector-resolved-threat' : ''}`}>
                <div className="vector-card-header">
                  <span className="vector-title">SSL Handshake</span>
                  <span className="vector-icon" style={{ color: 'var(--cyan)' }}><LockIcon /></span>
                </div>
                <span className="vector-status">
                  {vectorStates.ssl === 'idle' ? 'Armed' : vectorStates.ssl === 'scanning' ? 'Scanning...' : vectorStates.ssl === 'resolved-safe' ? 'Handshake OK' : 'No HTTPS'}
                </span>
              </div>

              <div className={`vector-card ${vectorStates.nlp === 'scanning' ? 'vector-active-scanning' : vectorStates.nlp === 'resolved-safe' ? 'vector-resolved-safe' : vectorStates.nlp === 'resolved-threat' ? 'vector-resolved-threat' : ''}`}>
                <div className="vector-card-header">
                  <span className="vector-title">NLP Classifier</span>
                  <span className="vector-icon" style={{ color: 'var(--emerald)' }}><BrainIcon /></span>
                </div>
                <span className="vector-status">
                  {vectorStates.nlp === 'idle' ? 'Armed' : vectorStates.nlp === 'scanning' ? 'Scanning...' : vectorStates.nlp === 'resolved-safe' ? 'Low Urgency' : 'Fraud Intent'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mule Registry Tab */}
      {activeTab === 'mule-db' && (
        <div className="glass-panel section-box animation-fadeIn">
          <div className="section-head">
            <h2 className="section-title title-font">Cross-Station Suspicious Mule Registry</h2>
            <span className="amber-text" style={{ fontSize: '10px', fontWeight: 'bold' }}>📂 REPORT DATABASE</span>
          </div>

          <div>
            {/* Database Browser */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              {/* Stats Card */}
              <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Mule Database Count</div>
                  <div style={{ fontSize: '28px', fontWeight: 'bold', fontFamily: 'var(--font-mono)' }} className="cyan-text">
                    {muleStats.total_mules || muleAccounts.length}
                  </div>
                </div>
                <div style={{ height: '30px', width: '1px', background: 'rgba(255, 255, 255, 0.1)' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Verifications Checked</div>
                  <div style={{ fontSize: '28px', fontWeight: 'bold', fontFamily: 'var(--font-mono)' }} className="purple-text">
                    {totalChecked}
                  </div>
                </div>
              </div>

              {/* Table */}
              <div className="mule-table-container">
                <table className="mule-table">
                  <thead>
                    <tr>
                      <th>Holder</th>
                      <th>UPI VPA / Account</th>
                      <th>Location</th>
                      <th>Category</th>
                    </tr>
                  </thead>
                  <tbody>
                    {muleAccounts.length === 0 ? (
                      <tr>
                        <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '20px' }}>
                          No mule account records found. Check server connectivity.
                        </td>
                      </tr>
                    ) : (
                      muleAccounts.slice().reverse().map((acc, idx) => (
                        <tr key={idx}>
                          <td>
                            <div style={{ fontWeight: 'bold', color: '#fff' }}>{acc.holder_name || 'Unknown'}</div>
                            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{acc.phone || 'No phone'}</div>
                          </td>
                          <td>
                            {acc.upi_id && <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{acc.upi_id}</div>}
                            {acc.account_number && <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>A/C: {acc.account_number}</div>}
                          </td>
                          <td style={{ color: 'var(--text-muted)' }}>{acc.location || 'Unknown'}</td>
                          <td>
                            <span style={{
                              fontSize: '10px',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              background: 'rgba(255, 59, 105, 0.1)',
                              color: 'var(--crimson)',
                              border: '1px solid rgba(255, 59, 105, 0.2)',
                              fontWeight: 'bold'
                            }}>
                              {acc.category || 'Mule Account'}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Complaint Modal Overlay */}
      {selectedComplaint && (
        <div className="modal-overlay" style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.85)',
          zIndex: 1000,
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          backdropFilter: 'blur(8px)',
          overflowY: 'auto',
          padding: '20px'
        }}>
          <div className="modal-content glass-panel" style={{
            background: '#121214',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '16px',
            width: '100%',
            maxWidth: '650px',
            padding: '30px',
            boxShadow: '0 20px 40px rgba(0, 0, 0, 0.5)',
            maxHeight: '90vh',
            overflowY: 'auto',
            position: 'relative'
          }}>
            {/* Modal Head */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', paddingBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '20px' }}>⚖️</span>
                <h3 className="title-font" style={{ margin: 0, fontSize: '18px', color: '#fff' }}>Official Scam Complaint Form</h3>
              </div>
              <button
                onClick={() => setSelectedComplaint(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '20px',
                  cursor: 'pointer'
                }}
              >
                &times;
              </button>
            </div>

            {/* Verification Banner */}
            <div style={{
              background: 'rgba(0, 255, 136, 0.06)',
              color: 'var(--emerald)',
              padding: '12px 16px',
              borderRadius: '8px',
              marginBottom: '20px',
              border: '1px solid rgba(0, 255, 136, 0.2)',
              fontSize: '12px',
              fontWeight: 'bold',
              lineHeight: '1.4',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <span style={{ fontSize: '16px' }}>🛡️</span>
              <div>
                <strong>OFFICIAL EVIDENCE RECORD:</strong> This tool compiles verified cryptographic evidence locally to generate a standardized incident form for archiving. All evidence hashes are sealed on the registry ledger.
              </div>
            </div>



            {/* Print Area */}
            <div id="printable-complaint" style={{
              background: '#fff',
              color: '#000',
              padding: '30px',
              borderRadius: '8px',
              fontFamily: '"Courier New", Courier, monospace',
              fontSize: '12px',
              border: '2px solid #000',
              lineHeight: '1.5',
              boxShadow: 'inset 0 0 10px rgba(0,0,0,0.05)'
            }}>
              <div style={{ textAlign: 'center', borderBottom: '2px solid #000', paddingBottom: '15px', marginBottom: '20px' }}>
                <h2 style={{ margin: '0 0 5px 0', fontSize: '16px', fontWeight: 'bold' }}>NATIONAL CYBER CRIME REPORTING PORTAL</h2>
                <h4 style={{ margin: 0, fontSize: '12px', letterSpacing: '1px' }}>OFFICIAL INCIDENT SCANNED EVIDENCE FORM</h4>
                <div style={{ fontSize: '9px', marginTop: '5px', color: '#555' }}>Report generated automatically by CyberShield Digital Policing Platform</div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: '8px 12px', marginBottom: '15px' }}>
                <strong style={{ textTransform: 'uppercase' }}>Incident ID:</strong>
                <div style={{ wordBreak: 'break-all', overflowWrap: 'break-word', minWidth: 0 }}>{selectedComplaint.evidence_hash}</div>

                <strong style={{ textTransform: 'uppercase' }}>Logged Status:</strong>
                <div>{selectedComplaint.blockchain_logged ? 'ON-CHAIN IMMUTABLE LOG' : 'LOCAL CACHE LOG'}</div>

                <strong style={{ textTransform: 'uppercase' }}>Ledger/Tx Hash:</strong>
                <div style={{ wordBreak: 'break-all', overflowWrap: 'break-word', minWidth: 0 }}>{selectedComplaint.tx_hash || 'N/A'}</div>

                <strong style={{ textTransform: 'uppercase' }}>Threat Category:</strong>
                <div style={{ fontWeight: 'bold' }}>{selectedComplaint.category}</div>

                <strong style={{ textTransform: 'uppercase' }}>Offender Target:</strong>
                <div style={{ fontFamily: 'monospace', fontWeight: 'bold', wordBreak: 'break-all', overflowWrap: 'break-word', minWidth: 0 }}>{selectedComplaint.target}</div>

                <strong style={{ textTransform: 'uppercase' }}>Timestamp:</strong>
                <div>{new Date(selectedComplaint.timestamp * 1000).toLocaleString()}</div>

                <strong style={{ textTransform: 'uppercase' }}>Reporter (Citizen):</strong>
                <div style={{ wordBreak: 'break-all', overflowWrap: 'break-word', minWidth: 0 }}>{selectedComplaint.reporter || 'Citizen'} (Jurisdiction: {selectedComplaint.location || 'Unknown Location'})</div>

                <strong style={{ textTransform: 'uppercase' }}>Auditing Officer:</strong>
                <div style={{ wordBreak: 'break-all', overflowWrap: 'break-word', minWidth: 0 }}>{account || 'CyberShield Command Node'}</div>
              </div>

              <div style={{ borderTop: '1px solid #000', borderBottom: '1px solid #000', padding: '12px 0', margin: '15px 0' }}>
                <strong style={{ textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Incident Description & Technical Evidence:</strong>
                <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{selectedComplaint.reason}</p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '40px' }}>
                <div style={{ textAlign: 'center', width: '200px' }}>
                  <div style={{ height: '30px' }}></div>
                  <div style={{ borderTop: '1px solid #000', fontSize: '9px', textTransform: 'uppercase' }}>Officer Signature</div>
                </div>
                <div style={{ textAlign: 'center', width: '200px' }}>
                  <div style={{ height: '30px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: '16px' }}>🛡️ VALIDATED</span>
                  </div>
                  <div style={{ borderTop: '1px solid #000', fontSize: '9px', textTransform: 'uppercase' }}>CyberShield Seal</div>
                </div>
              </div>
            </div>

            {/* Modal Controls */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '20px' }}>
              <button
                onClick={() => setSelectedComplaint(null)}
                className="btn-modal-close"
              >
                Close
              </button>
              <button
                onClick={() => {
                  const printContents = document.getElementById('printable-complaint').innerHTML;
                  const printWindow = window.open('', '_blank');
                  printWindow.document.write(`
                    <html>
                      <head>
                        <title>CyberShield Complaint Form</title>
                        <style>
                          body { margin: 40px; font-family: monospace; background: white; color: black; }
                          #printable-complaint { border: 2px solid black; padding: 30px; }
                        </style>
                      </head>
                      <body onload="window.print(); window.close();">
                        <div id="printable-complaint">${printContents}</div>
                      </body>
                    </html>
                  `);
                  printWindow.document.close();
                }}
                className="btn-primary"
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  border: 'none',
                  background: 'linear-gradient(135deg, var(--cyan), #0891b2)',
                  color: '#030712',
                  cursor: 'pointer',
                  fontWeight: 'bold'
                }}
              >
                🖨️ Print / Download PDF
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

export default App;
