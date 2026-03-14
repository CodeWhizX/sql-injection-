import React, { useState, useEffect, useRef } from 'react';
import { ShieldAlert, Play, Square, Activity, Database, AlertTriangle, CheckCircle, Search, Terminal, FileJson, Download, ListFilter, FileText, Copy, Check, RefreshCw, Bot, Shield, Key, ToggleLeft, ToggleRight, Clock, Settings, LayoutDashboard, Code } from 'lucide-react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, Legend } from 'recharts';

// Types
type ScanStatus = 'idle' | 'scanning' | 'completed' | 'stopped';
type Severity = 'High' | 'Medium' | 'Low' | 'Info';
type DetectionMethod = 'Error-Based' | 'Boolean-Based' | 'Time-Based' | 'Response Comparison' | 'AI Anomaly';

interface LogEntry {
  id: number;
  time?: string;
  timestamp?: string;
  method?: string;
  url?: string;
  status?: number;
  length?: number;
  responseTime: number;
  payload?: string;
  type?: 'info' | 'success' | 'warning' | 'error';
  message?: string;
}

interface Finding {
  id: number;
  parameter: string;
  method: DetectionMethod;
  payload: string;
  confidence: number;
  dbGuess: string;
  severity: Severity;
  request: string;
  response: string;
}

interface DetectedParameter {
  id: number;
  name: string;
  method: string;
  type: string;
  baselineValue: string;
}

// Mock Data Generators
const generateMockLogs = (target: string, count: number): LogEntry[] => {
  const logs: LogEntry[] = [];
  const methods = ['GET', 'POST'];
  const payloads = ["'", "1=1", "' OR '1'='1", "SLEEP(5)", "WAITFOR DELAY '0:0:5'", "UNION SELECT NULL--"];
  
  for (let i = 0; i < count; i++) {
    logs.push({
      id: Date.now() + i,
      time: new Date().toLocaleTimeString(),
      method: methods[Math.floor(Math.random() * methods.length)],
      url: `${target}/api/data?id=${Math.floor(Math.random() * 100)}`,
      status: Math.random() > 0.8 ? 500 : 200,
      length: Math.floor(Math.random() * 5000) + 500,
      responseTime: Math.floor(Math.random() * 200) + 20,
      payload: payloads[Math.floor(Math.random() * payloads.length)],
    });
  }
  return logs;
};

const mockParameters: DetectedParameter[] = [
  { id: 1, name: 'id', method: 'GET', type: 'URL Query', baselineValue: '12' },
  { id: 2, name: 'search', method: 'GET', type: 'URL Query', baselineValue: 'test' },
  { id: 3, name: 'username', method: 'POST', type: 'Form Field', baselineValue: 'admin' },
  { id: 4, name: 'password', method: 'POST', type: 'Form Field', baselineValue: '********' },
  { id: 5, name: 'session_id', method: 'COOKIE', type: 'HTTP Header', baselineValue: 'abc123xyz' },
];

const fingerprintDatabase = (response: string, payload: string): string => {
  const respLower = response.toLowerCase();
  const payloadLower = payload.toLowerCase();

  // 1. Error-based fingerprinting
  if (respLower.includes('mysql') || respLower.includes('you have an error in your sql syntax')) {
    return 'MySQL';
  }
  if (respLower.includes('postgresql') || respLower.includes('syntax error at or near') || respLower.includes('pg::')) {
    return 'PostgreSQL';
  }
  if (respLower.includes('sql server') || respLower.includes('microsoft ole db') || respLower.includes('unclosed quotation mark')) {
    return 'MSSQL';
  }
  if (respLower.includes('ora-') || respLower.includes('oracle') || respLower.includes('quoted string not properly terminated')) {
    return 'Oracle';
  }
  if (respLower.includes('sqlite') || respLower.includes('unrecognized token')) {
    return 'SQLite';
  }

  // 2. Payload/Time-based fingerprinting
  if (payloadLower.includes('waitfor delay')) return 'MSSQL';
  if (payloadLower.includes('pg_sleep')) return 'PostgreSQL';
  if (payloadLower.includes('sleep(')) return 'MySQL';
  if (payloadLower.includes('dbms_lock.sleep')) return 'Oracle';

  return 'Unknown';
};

const rawMockFindings = [
  {
    id: 1,
    parameter: 'id (GET)',
    method: 'Error-Based' as const,
    payload: "'",
    confidence: 98,
    severity: 'High' as const,
    request: "GET /api/users?id=1' HTTP/1.1\nHost: target.local\nUser-Agent: EduScanner/1.0",
    response: "HTTP/1.1 500 Internal Server Error\nContent-Type: text/html\n\n... You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1 ..."
  },
  {
    id: 2,
    parameter: 'username (POST)',
    method: 'Boolean-Based' as const,
    payload: "' OR '1'='1",
    confidence: 85,
    severity: 'Medium' as const,
    request: "POST /login HTTP/1.1\nHost: target.local\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR '1'='1&password=foo",
    response: "HTTP/1.1 200 OK\nContent-Length: 4502\n\n... Welcome back, admin! ..."
  },
  {
    id: 3,
    parameter: 'search (GET)',
    method: 'Time-Based' as const,
    payload: "1'; WAITFOR DELAY '0:0:5'--",
    confidence: 92,
    severity: 'Low' as const,
    request: "GET /search?q=1'; WAITFOR DELAY '0:0:5'-- HTTP/1.1\nHost: target.local",
    response: "HTTP/1.1 200 OK\nContent-Length: 120\n\n... No results found ...\n[Response Time: 5042ms]"
  },
  {
    id: 4,
    parameter: 'sort (GET)',
    method: 'Error-Based' as const,
    payload: "1; SELECT pg_sleep(5)--",
    confidence: 95,
    severity: 'High' as const,
    request: "GET /items?sort=1; SELECT pg_sleep(5)-- HTTP/1.1\nHost: target.local",
    response: "HTTP/1.1 500 Internal Server Error\nContent-Length: 230\n\n... ERROR: syntax error at or near \";\" ..."
  }
];

const mockFindings: Finding[] = rawMockFindings.map(f => ({
  ...f,
  dbGuess: fingerprintDatabase(f.response, f.payload)
}));

const aiMockFinding: Finding = {
  id: 5,
  parameter: 'session_id (COOKIE)',
  method: 'AI Anomaly',
  payload: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'",
  confidence: 88,
  dbGuess: 'Unknown',
  severity: 'High',
  request: "GET /profile HTTP/1.1\nHost: target.local\nCookie: session_id=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'",
  response: "HTTP/1.1 200 OK\nContent-Length: 420\n\n... [AI Analysis: 94% deviation from baseline response structure. Suspicious data reflection detected despite 200 OK status. Possible blind injection.] ..."
};

const mockWafResponses = [
  "HTTP/1.1 403 Forbidden\nServer: cloudflare\nCF-RAY: 1234567890abcdef\n\n...",
  "HTTP/1.1 403 Forbidden\nX-Amzn-RequestId: 1234567890abcdef\n\n...",
  "HTTP/1.1 406 Not Acceptable\nServer: Apache\nModSecurity Action\n\n...",
  "HTTP/1.1 403 Forbidden\nX-Sucuri-ID: 12345\n\n...",
  "HTTP/1.1 403 Forbidden\nServer: AkamaiGHost\n\n...",
  "HTTP/1.1 403 Forbidden\nSet-Cookie: BIGipServer=12345\n\n...",
  "HTTP/1.1 403 Forbidden\nServer: FortiWeb\n\n...",
  "HTTP/1.1 200 OK\nServer: nginx\n\n..." // None
];

const analyzeWafPresence = (response: string): string => {
  const respLower = response.toLowerCase();
  
  // Cloudflare
  if (respLower.includes('server: cloudflare') || respLower.includes('cf-ray') || respLower.includes('__cfduid')) return 'Cloudflare (Detected)';
  
  // AWS WAF
  if (respLower.includes('x-amzn-requestid') || respLower.includes('awselb') || respLower.includes('x-amz-cf-id')) return 'AWS WAF (Detected)';
  
  // ModSecurity
  if (respLower.includes('modsecurity') || respLower.includes('406 not acceptable') || respLower.includes('mod_security')) return 'ModSecurity (Detected)';
  
  // Sucuri
  if (respLower.includes('x-sucuri-id') || respLower.includes('server: sucuri') || respLower.includes('sucuri/cloudproxy')) return 'Sucuri (Detected)';
  
  // Imperva / Incapsula
  if (respLower.includes('x-iinfo') || respLower.includes('incapsula') || respLower.includes('visid_incap')) return 'Imperva (Detected)';
  
  // Akamai
  if (respLower.includes('akamaighost') || respLower.includes('x-akamai') || respLower.includes('akamai-gws')) return 'Akamai (Detected)';
  
  // F5 BIG-IP
  if (respLower.includes('bigip') || respLower.includes('f5-trafficshield') || respLower.includes('x-cnection')) return 'F5 BIG-IP (Detected)';
  
  // Barracuda
  if (respLower.includes('barra_') || respLower.includes('bniscan')) return 'Barracuda (Detected)';

  // Fortinet
  if (respLower.includes('fortiweb') || respLower.includes('fortigate')) return 'Fortinet (Detected)';

  // Generic WAF block patterns
  if (respLower.includes('blocked by waf') || respLower.includes('web application firewall') || respLower.includes('security policy violation')) return 'Generic WAF (Detected)';

  return 'None Detected';
};

const simulateWafBypass = (wafType: string): string => {
  if (wafType === 'None Detected') return 'None Detected';
  if (wafType === 'Unknown') return 'Unknown';
  
  const bypassTechniques = [
    'HTTP Parameter Pollution (HPP)',
    'Chunked Transfer Encoding',
    'Unicode Normalization',
    'SQL Comment Obfuscation (/**/)',
    'Whitespace Evasion (%0a, %09)',
    'Case Toggling (SeLeCt)',
    'URL Encoding (%27)',
    'Double URL Encoding (%2527)',
    'Hex Encoding (0x27)'
  ];
  
  const technique = bypassTechniques[Math.floor(Math.random() * bypassTechniques.length)];
  const isBypassed = Math.random() > 0.3; // 70% chance to bypass
  
  if (isBypassed) {
    return `${wafType.split(' ')[0]} (Bypassed via ${technique})`;
  } else {
    return `${wafType.split(' ')[0]} (Detected - Blocked)`;
  }
};

export default function App() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080/dvwa');
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [parameters, setParameters] = useState<DetectedParameter[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [progress, setProgress] = useState(0);
  const [scanSpeed, setScanSpeed] = useState<'Slow' | 'Normal' | 'Aggressive'>('Normal');
  const [rateLimit, setRateLimit] = useState<number>(0);
  const [copiedReq, setCopiedReq] = useState(false);
  const [copiedRes, setCopiedRes] = useState(false);
  const [wafStatus, setWafStatus] = useState<string>('Unknown');
  const [aiMode, setAiMode] = useState(false);
  const [authConfigured, setAuthConfigured] = useState(false);
  const [scanPhase, setScanPhase] = useState<string>('Idle');
  const [activeTab, setActiveTab] = useState<'scanner' | 'dashboard' | 'settings'>('scanner');
  const [chartData, setChartData] = useState<any[]>([]);
  const [plugins, setPlugins] = useState({
    formAutoSubmit: true,
    apiScanning: true,
    sessionHandling: false,
    payloadEncoding: true,
    responseSimilarity: true,
    timingAnalysis: true,
    falsePositiveReduction: true,
  });
  const [scheduledTime, setScheduledTime] = useState('');
  const [replayRequest, setReplayRequest] = useState('');
  const [replayResponse, setReplayResponse] = useState('');
  const [isReplaying, setIsReplaying] = useState(false);
  
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll console
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // WAF Detection Reaction
  useEffect(() => {
    if (wafStatus.endsWith('(Detected)')) {
      setScanSpeed('Slow');
      setPlugins(p => ({ ...p, payloadEncoding: true, timingAnalysis: true }));
      setLogs(prev => [...prev.slice(-49), {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        type: 'info',
        message: `WAF Detected: ${wafStatus.split(' ')[0]}. Adjusting scan speed to Slow and enabling payload encoding evasion.`,
        responseTime: 0
      }]);
    }
  }, [wafStatus]);

  // Simulation Logic
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (status === 'scanning') {
      let currentProgress = 0;
      
      const baseDelay = scanSpeed === 'Slow' ? 1000 : scanSpeed === 'Aggressive' ? 150 : 500;
      const rateLimitDelay = rateLimit > 0 ? 1000 / rateLimit : 0;
      const delay = Math.max(baseDelay, rateLimitDelay);
      
      const progressIncrement = scanSpeed === 'Slow' ? 2 : scanSpeed === 'Aggressive' ? 10 : 5;

      interval = setInterval(() => {
        currentProgress += Math.random() * progressIncrement;
        if (currentProgress >= 100) {
          currentProgress = 100;
          setStatus('completed');
          setScanPhase('Completed');
          setFindings(aiMode ? [...mockFindings, aiMockFinding] : mockFindings);
        } else if (currentProgress < 20) {
          setScanPhase('Crawling & Discovery');
          if (currentProgress > 5 && currentProgress <= 15) {
            setWafStatus(prev => {
              if (prev === 'Detecting...') {
                const randomResponse = mockWafResponses[Math.floor(Math.random() * mockWafResponses.length)];
                return analyzeWafPresence(randomResponse);
              }
              return prev;
            });
          }
          if (currentProgress > 15) {
            setWafStatus(prev => {
              if (prev.endsWith('(Detected)')) {
                return simulateWafBypass(prev);
              }
              return prev;
            });
          }
        } else {
          setScanPhase('Active Scanning');
        }
        setProgress(currentProgress);
        
        // Add a log entry
        const newLog = generateMockLogs(targetUrl.split('\n')[0] || 'http://localhost', 1)[0];
        setLogs(prev => [...prev.slice(-49), newLog]); // Keep last 50 logs
        
        // Update chart data
        setChartData(prev => {
          const newData = [...prev, {
            time: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            requests: Math.floor(Math.random() * 50) + 10,
            responseTime: newLog.responseTime
          }];
          return newData.slice(-20); // Keep last 20 data points
        });
        
        // Randomly add findings during scan
        if (currentProgress > 10 && parameters.length === 0) setParameters(mockParameters.slice(0, 2));
        if (currentProgress > 20 && parameters.length === 2) setParameters(mockParameters);
        if (currentProgress > 30 && findings.length === 0) setFindings([mockFindings[0]]);
        if (currentProgress > 60 && findings.length === 1) setFindings([mockFindings[0], mockFindings[1]]);
        if (currentProgress > 80 && findings.length === 2 && aiMode) setFindings([mockFindings[0], mockFindings[1], aiMockFinding]);
        
      }, delay);
    }
    return () => clearInterval(interval);
  }, [status, targetUrl, findings.length, scanSpeed, rateLimit, aiMode]);

  const handleStart = () => {
    if (!targetUrl) return;
    setStatus('scanning');
    setScanPhase('Initializing');
    setWafStatus('Detecting...');
    
    const initialLogs: LogEntry[] = [];
    if (authConfigured) {
      initialLogs.push({
        id: Date.now() - 2,
        timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        type: 'info',
        message: 'Authenticating with target and establishing session cookies...',
        responseTime: 120
      });
      initialLogs.push({
        id: Date.now() - 1,
        timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        type: 'success',
        message: 'Session established successfully. Maintaining cookies for authenticated scan.',
        responseTime: 45
      });
    }
    if (aiMode) {
      initialLogs.push({
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        type: 'info',
        message: 'AI Anomaly Detection enabled. Analyzing baseline response structures.',
        responseTime: 0
      });
    }
    
    setLogs(initialLogs);
    setFindings([]);
    setParameters([]);
    setProgress(0);
    setSelectedFinding(null);
    setChartData([]);
  };

  const handleSchedule = () => {
    if (!scheduledTime) return;
    alert(`Scan scheduled for ${scheduledTime}`);
  };

  const handleReplay = () => {
    setIsReplaying(true);
    setTimeout(() => {
      setReplayResponse(`HTTP/1.1 200 OK\nServer: Replay-Server\nContent-Type: text/html\n\n... Replay response for payload ...\n[Simulated Response Time: ${Math.floor(Math.random() * 500) + 50}ms]`);
      setIsReplaying(false);
    }, 800);
  };

  const generatePoC = (finding: Finding) => {
    const poc = `import requests

url = "${targetUrl.split('\n')[0] || 'http://localhost'}"
payload = "${finding.payload.replace(/"/g, '\\"')}"

# Auto-generated PoC for ${finding.parameter}
print(f"Testing {url} with payload: {payload}")
# Add your request logic here
`;
    navigator.clipboard.writeText(poc);
    alert('Proof of Concept script copied to clipboard!');
  };

  const handleStop = () => {
    setStatus('stopped');
  };

  const exportJSON = () => {
    const report = {
      target: targetUrl,
      scanDate: new Date().toISOString(),
      summary: {
        totalRequests: logs.length,
        findingsCount: findings.length,
        parametersCount: parameters.length
      },
      parameters,
      findings
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `eduscanner_report_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const exportPDF = () => {
    const doc = new jsPDF();
    
    doc.setFontSize(20);
    doc.text('EduScanner SQLi Report', 14, 22);
    
    doc.setFontSize(12);
    doc.text(`Target: ${targetUrl}`, 14, 32);
    doc.text(`Date: ${new Date().toLocaleString()}`, 14, 40);
    doc.text(`Total Findings: ${findings.length}`, 14, 48);

    if (findings.length > 0) {
      doc.setFontSize(16);
      doc.text('Vulnerabilities', 14, 60);
      
      autoTable(doc, {
        startY: 65,
        head: [['Parameter', 'Method', 'Severity', 'Confidence', 'DB Guess']],
        body: findings.map(f => [f.parameter, f.method, f.severity, `${f.confidence}%`, f.dbGuess]),
        theme: 'grid',
        headStyles: { fillColor: [16, 185, 129] } // Emerald 500
      });
    }

    doc.save(`eduscanner_report_${Date.now()}.pdf`);
  };

  const handleCopy = (text: string, type: 'req' | 'res') => {
    navigator.clipboard.writeText(text);
    if (type === 'req') {
      setCopiedReq(true);
      setTimeout(() => setCopiedReq(false), 2000);
    } else {
      setCopiedRes(true);
      setTimeout(() => setCopiedRes(false), 2000);
    }
  };

  const renderHighlightedText = (text: string, highlight: string) => {
    if (!highlight) return text;
    const parts = text.split(highlight);
    return parts.map((part, i) => (
      <React.Fragment key={i}>
        {part}
        {i < parts.length - 1 && (
          <span className="bg-yellow-500/40 text-yellow-200 px-1 rounded font-bold">{highlight}</span>
        )}
      </React.Fragment>
    ));
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-300 font-mono selection:bg-emerald-500/30">
      {/* Safety Banner */}
      <div className="bg-amber-500/10 border-b border-amber-500/20 text-amber-400 px-4 py-2 flex items-center justify-center text-sm font-semibold tracking-wide">
        <ShieldAlert className="w-4 h-4 mr-2" />
        THIS TOOL IS FOR SECURITY EDUCATION AND AUTHORIZED PENETRATION TESTING ONLY
      </div>

      <div className="max-w-7xl mx-auto p-4 space-y-4">
        {/* Header */}
        <header className="flex items-center justify-between pb-4 border-b border-zinc-800">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
              <Database className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-zinc-100">EduScanner SQLi</h1>
              <p className="text-xs text-zinc-500">Educational Vulnerability Detection Engine</p>
            </div>
          </div>
          <div className="flex items-center space-x-4 text-sm">
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${status === 'scanning' ? 'bg-emerald-500 animate-pulse' : 'bg-zinc-600'}`} />
              <span className="uppercase text-zinc-400">{status === 'scanning' ? scanPhase : status}</span>
            </div>
          </div>
        </header>

        {/* Tab Navigation */}
        <div className="flex space-x-6 border-b border-zinc-800">
          <button 
            onClick={() => setActiveTab('scanner')} 
            className={`pb-3 px-1 text-sm font-medium flex items-center space-x-2 transition-colors ${activeTab === 'scanner' ? 'text-emerald-400 border-b-2 border-emerald-400' : 'text-zinc-500 hover:text-zinc-300'}`}
          >
            <Terminal className="w-4 h-4" />
            <span>Scanner</span>
          </button>
          <button 
            onClick={() => setActiveTab('dashboard')} 
            className={`pb-3 px-1 text-sm font-medium flex items-center space-x-2 transition-colors ${activeTab === 'dashboard' ? 'text-emerald-400 border-b-2 border-emerald-400' : 'text-zinc-500 hover:text-zinc-300'}`}
          >
            <LayoutDashboard className="w-4 h-4" />
            <span>Analytics Dashboard</span>
          </button>
          <button 
            onClick={() => setActiveTab('settings')} 
            className={`pb-3 px-1 text-sm font-medium flex items-center space-x-2 transition-colors ${activeTab === 'settings' ? 'text-emerald-400 border-b-2 border-emerald-400' : 'text-zinc-500 hover:text-zinc-300'}`}
          >
            <Settings className="w-4 h-4" />
            <span>Settings & Plugins</span>
          </button>
        </div>

        {activeTab === 'scanner' && (
          <>
            {/* Configuration Panel */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3 bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
              <div className="flex-1 space-y-1">
                <label className="text-xs text-zinc-500 uppercase tracking-wider">Target URLs (One per line)</label>
                <div className="relative">
                  <Search className="absolute left-3 top-3 w-4 h-4 text-zinc-500" />
                  <textarea 
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    disabled={status === 'scanning'}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 disabled:opacity-50 transition-all resize-none h-10 focus:h-24"
                    placeholder="http://example.com/vulnerable&#10;http://example.com/api"
                  />
                </div>
              </div>
              <div className="w-full sm:w-32 space-y-1">
                <label className="text-xs text-zinc-500 uppercase tracking-wider">Depth</label>
                <select disabled={status === 'scanning'} className="w-full bg-zinc-950 border border-zinc-800 rounded-lg py-2 px-3 text-sm focus:outline-none focus:border-emerald-500/50 disabled:opacity-50">
                  <option>Level 1</option>
                  <option>Level 2</option>
                  <option>Level 3</option>
                </select>
              </div>
              <div className="w-full sm:w-32 space-y-1">
                <label className="text-xs text-zinc-500 uppercase tracking-wider">Speed</label>
                <select 
                  value={scanSpeed}
                  onChange={(e) => setScanSpeed(e.target.value as 'Slow' | 'Normal' | 'Aggressive')}
                  disabled={status === 'scanning'} 
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg py-2 px-3 text-sm focus:outline-none focus:border-emerald-500/50 disabled:opacity-50"
                >
                  <option value="Slow">Slow</option>
                  <option value="Normal">Normal</option>
                  <option value="Aggressive">Aggressive</option>
                </select>
              </div>
              <div className="w-full sm:w-32 space-y-1">
                <label className="text-xs text-zinc-500 uppercase tracking-wider">Rate Limit</label>
                <div className="relative">
                  <input 
                    type="number" 
                    min="0"
                    value={rateLimit || ''}
                    onChange={(e) => setRateLimit(Math.max(0, parseInt(e.target.value) || 0))}
                    disabled={status === 'scanning'}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg py-2 pl-3 pr-12 text-sm focus:outline-none focus:border-emerald-500/50 disabled:opacity-50"
                    placeholder="Off"
                  />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-zinc-500 pointer-events-none uppercase">req/s</span>
                </div>
              </div>
            </div>

            {/* Advanced Options Row */}
            <div className="flex flex-wrap items-center gap-4 pt-4 mt-4 border-t border-zinc-800/50">
              <div className="flex items-center space-x-2 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-1.5">
                <Shield className={`w-4 h-4 ${
                  wafStatus.includes('Bypassed') ? 'text-emerald-400' : 
                  wafStatus.includes('Detected') && wafStatus !== 'None Detected' ? 'text-red-400' : 
                  wafStatus === 'Detecting...' ? 'text-amber-400 animate-pulse' : 
                  'text-zinc-500'
                }`} />
                <span className="text-xs text-zinc-400">WAF: <span className="text-zinc-300 font-medium">{wafStatus}</span></span>
              </div>
              
              <button 
                onClick={() => setAiMode(!aiMode)}
                disabled={status === 'scanning'}
                className={`flex items-center space-x-2 border rounded-lg px-3 py-1.5 transition-colors disabled:opacity-50 ${aiMode ? 'bg-purple-500/10 border-purple-500/30 text-purple-400' : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:bg-zinc-900'}`}
              >
                <Bot className="w-4 h-4" />
                <span className="text-xs font-medium">AI Anomaly Detection</span>
                {aiMode ? <ToggleRight className="w-4 h-4 ml-1" /> : <ToggleLeft className="w-4 h-4 ml-1" />}
              </button>

              <button 
                onClick={() => setAuthConfigured(!authConfigured)}
                disabled={status === 'scanning'}
                className={`flex items-center space-x-2 border rounded-lg px-3 py-1.5 transition-colors disabled:opacity-50 ${authConfigured ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:bg-zinc-900'}`}
              >
                <Key className="w-4 h-4" />
                <span className="text-xs font-medium">Auth: {authConfigured ? 'Configured' : 'None'}</span>
              </button>
            </div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 flex flex-col justify-end space-y-3">
            {status === 'scanning' ? (
              <button onClick={handleStop} className="w-full flex items-center justify-center space-x-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg py-3 px-4 transition-colors font-medium">
                <Square className="w-4 h-4" />
                <span>Stop Scan</span>
              </button>
            ) : (
              <button onClick={handleStart} className="w-full flex items-center justify-center space-x-2 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 rounded-lg py-3 px-4 transition-colors font-bold shadow-[0_0_15px_rgba(16,185,129,0.3)]">
                <Play className="w-4 h-4 fill-current" />
                <span>Start Scan</span>
              </button>
            )}
            <div className="flex items-center space-x-2">
              <input 
                type="time" 
                value={scheduledTime}
                onChange={(e) => setScheduledTime(e.target.value)}
                disabled={status === 'scanning'}
                className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg py-2 px-3 text-sm focus:outline-none focus:border-emerald-500/50 disabled:opacity-50"
              />
              <button 
                onClick={handleSchedule}
                disabled={status === 'scanning' || !scheduledTime}
                className="bg-zinc-800 text-zinc-300 hover:bg-zinc-700 disabled:opacity-50 px-3 py-2 rounded-lg transition-colors flex items-center"
                title="Schedule Scan"
              >
                <Clock className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        {(status === 'scanning' || status === 'completed') && (
          <div className="h-1 w-full bg-zinc-900 rounded-full overflow-hidden">
            <div 
              className="h-full bg-emerald-500 transition-all duration-300 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-[600px]">
          {/* Left Column: Live Console & Stats */}
          <div className="lg:col-span-1 flex flex-col space-y-4">
            {/* Stats */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Requests</div>
                <div className="text-2xl text-zinc-100">{logs.length * 12}</div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Findings</div>
                <div className="text-2xl text-amber-400">{findings.length}</div>
              </div>
            </div>

            {/* Detected Parameters */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden flex flex-col h-48 shrink-0">
              <div className="bg-zinc-900 px-4 py-2 border-b border-zinc-800 flex items-center space-x-2">
                <ListFilter className="w-4 h-4 text-zinc-500" />
                <span className="text-xs text-zinc-400 uppercase tracking-wider">Detected Parameters</span>
              </div>
              <div className="flex-1 overflow-auto">
                <table className="w-full text-left text-[10px]">
                  <thead className="bg-zinc-950/50 text-zinc-500 sticky top-0">
                    <tr>
                      <th className="px-3 py-2 font-medium">Name</th>
                      <th className="px-3 py-2 font-medium">Parameter Type</th>
                      <th className="px-3 py-2 font-medium">Baseline Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/50">
                    {parameters.length === 0 ? (
                      <tr>
                        <td colSpan={3} className="px-3 py-4 text-center text-zinc-600">
                          {status === 'scanning' ? 'Crawling...' : 'No parameters detected.'}
                        </td>
                      </tr>
                    ) : (
                      parameters.map((p) => (
                        <tr key={p.id} className="hover:bg-zinc-800/50">
                          <td className="px-3 py-2 text-zinc-300 font-medium flex items-center space-x-1">
                            <span>{p.name}</span>
                            <span className="text-[8px] px-1 py-0.5 rounded bg-zinc-800 text-zinc-400">{p.method}</span>
                          </td>
                          <td className="px-3 py-2 text-zinc-400">{p.type}</td>
                          <td className="px-3 py-2 text-zinc-500 font-mono truncate max-w-[80px]">{p.baselineValue}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Live Console */}
            <div className="flex-1 bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden flex flex-col min-h-[150px]">
              <div className="bg-zinc-900 px-4 py-2 border-b border-zinc-800 flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-zinc-500" />
                <span className="text-xs text-zinc-400 uppercase tracking-wider">Live Console</span>
              </div>
              <div className="flex-1 p-4 overflow-y-auto text-[10px] space-y-1 font-mono leading-relaxed">
                {logs.map((log) => (
                  <div key={log.id} className="flex space-x-3 hover:bg-zinc-900/50 px-1 rounded">
                    {log.type ? (
                      <>
                        <span className="text-zinc-600 w-16 shrink-0">{log.timestamp || log.time}</span>
                        <span className={`flex-1 ${
                          log.type === 'error' ? 'text-red-400' :
                          log.type === 'warning' ? 'text-amber-400' :
                          log.type === 'success' ? 'text-emerald-400' :
                          'text-blue-400'
                        }`}>
                          [SYSTEM] {log.message}
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="text-zinc-600 w-16 shrink-0">{log.time}</span>
                        <span className={`w-10 shrink-0 ${log.method === 'GET' ? 'text-blue-400' : 'text-purple-400'}`}>{log.method}</span>
                        <span className={`w-8 shrink-0 ${log.status && log.status >= 500 ? 'text-red-400' : log.status && log.status >= 400 ? 'text-amber-400' : 'text-emerald-400'}`}>{log.status}</span>
                        <span className="text-zinc-500 w-12 shrink-0">{log.responseTime}ms</span>
                        <span className="text-zinc-300 truncate flex-1">{log.url}</span>
                      </>
                    )}
                  </div>
                ))}
                <div ref={consoleEndRef} />
              </div>
            </div>
          </div>

          {/* Right Column: Findings & Details */}
          <div className="lg:col-span-2 flex flex-col space-y-4">
            {/* Findings Table */}
            <div className="h-1/2 bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden flex flex-col">
              <div className="bg-zinc-900 px-4 py-2 border-b border-zinc-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                  <span className="text-xs text-zinc-400 uppercase tracking-wider">Vulnerability Results</span>
                </div>
                <div className="flex items-center space-x-3">
                  <button 
                    onClick={exportJSON}
                    disabled={status === 'scanning' || findings.length === 0}
                    className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center space-x-1 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <FileJson className="w-3 h-3" />
                    <span>JSON</span>
                  </button>
                  <button 
                    onClick={exportPDF}
                    disabled={status === 'scanning' || findings.length === 0}
                    className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center space-x-1 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <FileText className="w-3 h-3" />
                    <span>PDF</span>
                  </button>
                </div>
              </div>
              <div className="flex-1 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-zinc-950/50 text-zinc-500 sticky top-0">
                    <tr>
                      <th className="px-4 py-3 font-medium">Parameter</th>
                      <th className="px-4 py-3 font-medium">Method</th>
                      <th className="px-4 py-3 font-medium">Confidence</th>
                      <th className="px-4 py-3 font-medium">DB Guess</th>
                      <th className="px-4 py-3 font-medium">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/50">
                    {findings.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-8 text-center text-zinc-600">
                          {status === 'scanning' ? 'Analyzing parameters...' : 'No vulnerabilities detected.'}
                        </td>
                      </tr>
                    ) : (
                      findings.map((finding) => (
                        <tr 
                          key={finding.id} 
                          onClick={() => setSelectedFinding(finding)}
                          className={`cursor-pointer transition-colors ${selectedFinding?.id === finding.id ? 'bg-zinc-800' : 'hover:bg-zinc-800/50'}`}
                        >
                          <td className="px-4 py-3 text-zinc-300">{finding.parameter}</td>
                          <td className="px-4 py-3 text-zinc-400">{finding.method}</td>
                          <td className="px-4 py-3">
                            <div className="flex items-center space-x-2">
                              <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                                <div className="h-full bg-emerald-500" style={{ width: `${finding.confidence}%` }} />
                              </div>
                              <span className="text-emerald-400">{finding.confidence}%</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-zinc-400">{finding.dbGuess}</td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border ${
                              finding.severity === 'High' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                              finding.severity === 'Medium' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                              finding.severity === 'Low' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                              'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
                            }`}>
                              {finding.severity}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Request / Response Viewer */}
            <div className="flex-1 bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden flex flex-col">
              <div className="bg-zinc-900 px-4 py-2 border-b border-zinc-800 flex items-center space-x-2">
                <FileJson className="w-4 h-4 text-zinc-500" />
                <span className="text-xs text-zinc-400 uppercase tracking-wider">Request / Response Viewer</span>
              </div>
              <div className="flex-1 p-4 flex flex-col lg:flex-row gap-4 overflow-hidden">
                {selectedFinding ? (
                  <>
                    <div className="flex-1 flex flex-col space-y-2 overflow-hidden">
                      <div className="flex items-center justify-between">
                        <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Injected Request</div>
                        <div className="flex items-center space-x-3">
                          <button 
                            onClick={() => generatePoC(selectedFinding)}
                            className="text-zinc-500 hover:text-purple-400 transition-colors flex items-center space-x-1 bg-zinc-800/50 hover:bg-zinc-800 px-2 py-1 rounded text-[10px] uppercase tracking-wider"
                            title="Generate PoC"
                          >
                            <Code className="w-3 h-3" />
                            <span>Generate PoC</span>
                          </button>
                          <button 
                            onClick={handleReplay}
                            disabled={isReplaying}
                            className={`text-zinc-500 hover:text-blue-400 transition-colors flex items-center space-x-1 bg-zinc-800/50 hover:bg-zinc-800 px-2 py-1 rounded text-[10px] uppercase tracking-wider ${isReplaying ? 'opacity-50' : ''}`}
                            title="Replay Request"
                          >
                            <RefreshCw className={`w-3 h-3 ${isReplaying ? 'animate-spin' : ''}`} />
                            <span>Replay</span>
                          </button>
                          <button 
                            onClick={() => handleCopy(replayRequest || selectedFinding.request, 'req')}
                            className="text-zinc-500 hover:text-zinc-300 transition-colors flex items-center space-x-1 bg-zinc-800/50 hover:bg-zinc-800 px-2 py-1 rounded text-[10px] uppercase tracking-wider"
                            title="Copy Request"
                          >
                            {copiedReq ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedReq ? 'Copied' : 'Copy Request'}</span>
                          </button>
                        </div>
                      </div>
                      <textarea 
                        className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg p-3 overflow-auto text-xs text-zinc-300 whitespace-pre-wrap focus:outline-none focus:border-emerald-500/50 resize-none"
                        value={replayRequest || selectedFinding.request}
                        onChange={(e) => setReplayRequest(e.target.value)}
                      />
                    </div>
                    <div className="flex-1 flex flex-col space-y-2 overflow-hidden">
                      <div className="flex items-center justify-between">
                        <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Server Response</div>
                        <button 
                          onClick={() => handleCopy(replayResponse || selectedFinding.response, 'res')}
                          className="text-zinc-500 hover:text-zinc-300 transition-colors flex items-center space-x-1 bg-zinc-800/50 hover:bg-zinc-800 px-2 py-1 rounded text-[10px] uppercase tracking-wider"
                          title="Copy Response"
                        >
                          {copiedRes ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedRes ? 'Copied' : 'Copy Response'}</span>
                        </button>
                      </div>
                      <div className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg p-3 overflow-auto text-xs text-zinc-300 whitespace-pre-wrap">
                        {replayResponse || selectedFinding.response}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="flex-1 flex items-center justify-center text-sm text-zinc-600">
                    Select a finding to view request and response details.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
          </>
        )}

        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <h3 className="text-sm font-medium text-zinc-300 mb-4 flex items-center"><Activity className="w-4 h-4 mr-2" /> Traffic Analysis</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="time" stroke="#52525b" fontSize={10} />
                      <YAxis stroke="#52525b" fontSize={10} />
                      <RechartsTooltip contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', fontSize: '12px' }} />
                      <Line type="monotone" dataKey="requests" stroke="#10b981" strokeWidth={2} dot={false} isAnimationActive={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <h3 className="text-sm font-medium text-zinc-300 mb-4 flex items-center"><Clock className="w-4 h-4 mr-2" /> Response Times</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="time" stroke="#52525b" fontSize={10} />
                      <YAxis stroke="#52525b" fontSize={10} />
                      <RechartsTooltip contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', fontSize: '12px' }} />
                      <Line type="monotone" dataKey="responseTime" stroke="#8b5cf6" strokeWidth={2} dot={false} isAnimationActive={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <h3 className="text-sm font-medium text-zinc-300 mb-4 flex items-center"><Terminal className="w-4 h-4 mr-2" /> Tested Parameters</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'URL Query', value: parameters.filter(p => p.type === 'URL Query').length },
                          { name: 'Form Field', value: parameters.filter(p => p.type === 'Form Field').length },
                          { name: 'HTTP Header', value: parameters.filter(p => p.type === 'HTTP Header').length }
                        ].filter(d => d.value > 0)}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {
                          [
                            { name: 'URL Query', value: parameters.filter(p => p.type === 'URL Query').length },
                            { name: 'Form Field', value: parameters.filter(p => p.type === 'Form Field').length },
                            { name: 'HTTP Header', value: parameters.filter(p => p.type === 'HTTP Header').length }
                          ].filter(d => d.value > 0).map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={['#10b981', '#3b82f6', '#f59e0b'][index % 3]} />
                          ))
                        }
                      </Pie>
                      <RechartsTooltip contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', fontSize: '12px' }} itemStyle={{ color: '#e4e4e7' }} />
                      <Legend wrapperStyle={{ fontSize: '12px', color: '#a1a1aa' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <h3 className="text-sm font-medium text-zinc-300 mb-4 flex items-center"><ShieldAlert className="w-4 h-4 mr-2" /> Vulnerabilities Discovered</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={[
                      { name: 'High', count: findings.filter(f => f.severity === 'High').length, fill: '#ef4444' },
                      { name: 'Medium', count: findings.filter(f => f.severity === 'Medium').length, fill: '#f59e0b' },
                      { name: 'Low', count: findings.filter(f => f.severity === 'Low').length, fill: '#3b82f6' },
                      { name: 'Info', count: findings.filter(f => f.severity === 'Info').length, fill: '#6b7280' }
                    ]}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="name" stroke="#52525b" fontSize={12} />
                      <YAxis stroke="#52525b" fontSize={12} allowDecimals={false} />
                      <RechartsTooltip contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', fontSize: '12px' }} cursor={{fill: '#27272a'}} />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-6">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Scanner Modules</h3>
                
                <label className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Form Auto-Submission</div>
                    <div className="text-xs text-zinc-500">Automatically detect and test login/search forms</div>
                  </div>
                  <div onClick={() => setPlugins({...plugins, formAutoSubmit: !plugins.formAutoSubmit})}>
                    {plugins.formAutoSubmit ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                  </div>
                </label>

                <label className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">API Endpoint Scanning</div>
                    <div className="text-xs text-zinc-500">Parse and test JSON bodies in REST APIs</div>
                  </div>
                  <div onClick={() => setPlugins({...plugins, apiScanning: !plugins.apiScanning})}>
                    {plugins.apiScanning ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                  </div>
                </label>

                <label className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Session Handling</div>
                    <div className="text-xs text-zinc-500">Maintain cookies for authenticated scanning</div>
                  </div>
                  <div onClick={() => setPlugins({...plugins, sessionHandling: !plugins.sessionHandling})}>
                    {plugins.sessionHandling ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                  </div>
                </label>
              </div>

              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Analysis Engines</h3>
                
                <label className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Response Similarity</div>
                    <div className="text-xs text-zinc-500">Compare page structure instead of just length</div>
                  </div>
                  <div onClick={() => setPlugins({...plugins, responseSimilarity: !plugins.responseSimilarity})}>
                    {plugins.responseSimilarity ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                  </div>
                </label>

                <label className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Timing Analysis Engine</div>
                    <div className="text-xs text-zinc-500">Average multiple requests to reduce false positives</div>
                  </div>
                  <div onClick={() => setPlugins({...plugins, timingAnalysis: !plugins.timingAnalysis})}>
                    {plugins.timingAnalysis ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                  </div>
                </label>
              </div>
            </div>

            <div className="space-y-6">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Evasion & Encoding</h3>
                
                <label className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Payload Encoding Engine</div>
                    <div className="text-xs text-zinc-500">Use URL, double, and comment encoding to bypass simple input filters by obfuscating payloads so they aren't recognized by basic signature matching.</div>
                  </div>
                  <div onClick={() => setPlugins({...plugins, payloadEncoding: !plugins.payloadEncoding})}>
                    {plugins.payloadEncoding ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                  </div>
                </label>

                <label className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">False Positive Reduction</div>
                    <div className="text-xs text-zinc-500">Run confirmation tests before marking as vulnerable</div>
                  </div>
                  <div onClick={() => setPlugins({...plugins, falsePositiveReduction: !plugins.falsePositiveReduction})}>
                    {plugins.falsePositiveReduction ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                  </div>
                </label>
              </div>

              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Session Handling & Authentication</h3>
                
                <div className="space-y-4">
                  <div className="bg-zinc-950 p-4 rounded-lg border border-zinc-800">
                    <div className="flex items-center justify-between mb-4 cursor-pointer group" onClick={() => setAuthConfigured(!authConfigured)}>
                      <div>
                        <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Automated Login</div>
                        <div className="text-xs text-zinc-500">Allow the scanner to log in and maintain session cookies</div>
                      </div>
                      <div>
                        {authConfigured ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                      </div>
                    </div>
                    
                    {authConfigured && (
                      <div className="space-y-3 animate-in fade-in slide-in-from-top-2 duration-200 border-t border-zinc-800 pt-4">
                        <div>
                          <label className="text-xs text-zinc-500 uppercase tracking-wider">Login URL</label>
                          <input type="text" className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-sm mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300" placeholder="https://target.local/login" />
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="text-xs text-zinc-500 uppercase tracking-wider">Username</label>
                            <input type="text" className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-sm mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300" placeholder="admin" />
                          </div>
                          <div>
                            <label className="text-xs text-zinc-500 uppercase tracking-wider">Password</label>
                            <input type="password" className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-sm mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300" placeholder="••••••••" />
                          </div>
                        </div>
                        <button className="w-full mt-4 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 rounded py-2 text-sm transition-colors flex items-center justify-center space-x-2">
                          <Key className="w-4 h-4" />
                          <span>Authenticate & Maintain Session</span>
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs text-zinc-500 uppercase tracking-wider">Manual Custom Headers / Cookies</label>
                    <textarea 
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-sm focus:outline-none focus:border-emerald-500/50 resize-none h-32 font-mono text-zinc-400"
                      placeholder="Cookie: session_id=12345&#10;Authorization: Bearer token..."
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
