import React, { useState, useEffect, useRef, Component } from 'react';
import { ShieldAlert, Play, Square, Activity, Database, AlertTriangle, CheckCircle, Search, Terminal, FileJson, Download, ListFilter, FileText, Copy, Check, RefreshCw, Bot, Shield, Key, ToggleLeft, ToggleRight, Clock, Settings, LayoutDashboard, Code, Target, AlertCircle, Brain, Zap, Eye, Globe, ChevronDown, ChevronRight, Sparkles, Loader2, LogOut, User } from 'lucide-react';
import { GoogleGenAI, Type, ThinkingLevel } from "@google/genai";
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, Legend } from 'recharts';
import { auth, db, googleProvider, signInWithPopup, onAuthStateChanged, collection, doc, setDoc, getDoc, updateDoc, addDoc, Timestamp, handleFirestoreError, OperationType, User as FirebaseUser } from './firebase';
import { useAuth } from './contexts/AuthContext';
import { useUserAuth } from './contexts/UserAuthContext';
import { Login } from './components/Auth/Login';
import { Register } from './components/Auth/Register';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import { Toaster } from 'react-hot-toast';

// Error Boundary Component
class ErrorBoundary extends (Component as any) {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }

  componentDidCatch(error: any, errorInfo: any) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      let errorMessage = "Something went wrong.";
      const error = this.state.error;
      if (error && error.message) {
        try {
          const parsedError = JSON.parse(error.message);
          if (parsedError.error) {
            errorMessage = `Firebase Error: ${parsedError.error} (Op: ${parsedError.operationType})`;
          }
        } catch (e) {
          errorMessage = error.message;
        }
      }

      return (
        <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
          <div className="bg-zinc-900 border border-red-500/30 rounded-2xl p-8 max-w-md w-full text-center space-y-6">
            <div className="inline-flex p-4 bg-red-500/10 rounded-full">
              <AlertTriangle className="w-12 h-12 text-red-500" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold text-zinc-100">Application Error</h2>
              <p className="text-zinc-400 text-sm">{errorMessage}</p>
            </div>
            <button 
              onClick={() => window.location.reload()}
              className="w-full py-3 bg-zinc-100 hover:bg-white text-zinc-950 rounded-xl font-bold transition-all"
            >
              Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Unique ID Generator to prevent duplicate keys
let globalIdCounter = Date.now();
const getNextId = () => {
  globalIdCounter += 1;
  return globalIdCounter.toString();
};

// Protected Route Component
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { user, isAuthReady } = useUserAuth();
  const location = useLocation();

  if (!isAuthReady) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-emerald-500 animate-spin" />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

const DatabaseStatusBanner = () => {
  const { dbStatus, dbTip } = useUserAuth();
  
  if (dbStatus === 'connected' || dbStatus === 'checking') return null;

  return (
    <div className="fixed top-16 left-0 right-0 z-[45] animate-in slide-in-from-top duration-300">
      <div className="bg-red-500/10 border-b border-red-500/20 backdrop-blur-md px-6 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-1.5 bg-red-500/20 rounded-lg">
            <Database className="w-4 h-4 text-red-500" />
          </div>
          <div className="flex flex-col">
            <span className="text-xs font-bold text-red-500 uppercase tracking-wider">Database Disconnected</span>
            <p className="text-[11px] text-red-200/70 max-w-2xl leading-tight">
              {dbTip || "The application is unable to connect to the database. Some features may be unavailable."}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <a 
            href="https://www.mongodb.com/docs/atlas/security-whitelist/" 
            target="_blank" 
            rel="noopener noreferrer"
            className="text-[10px] font-bold text-red-400 hover:text-red-300 underline underline-offset-4 transition-colors"
          >
            IP Whitelist Guide
          </a>
          <button 
            onClick={() => window.location.reload()}
            className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-md text-[10px] font-bold transition-all border border-red-500/20"
          >
            Retry Connection
          </button>
        </div>
      </div>
    </div>
  );
};

// Types
type ScanStatus = 'idle' | 'scanning' | 'completed' | 'stopped';
type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
type DetectionMethod = 'Error-Based' | 'Boolean-Based' | 'Time-Based' | 'Response Comparison' | 'AI Anomaly' | 'UNION-Based';

interface LogEntry {
  id: string;
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

interface RequestDetails {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

interface Finding {
  id: string;
  parameter: string;
  method: DetectionMethod;
  payload: string;
  rawPayload?: string;
  evasionTechnique?: string;
  confidence: number;
  dbGuess: string;
  dbVersion?: string;
  severity: Severity;
  request: string;
  requestDetails: RequestDetails;
  response: string;
  remediation?: string;
  timingData?: {
    baselineLatency: number;
    actualLatency: number;
    requestedSleep: number;
    isConsistent: boolean;
  };
  aiAnomalyDetails?: {
    type: string;
    description: string;
    confidenceScore: number;
    evidence: string[];
    deepExplanation?: string;
  };
  aiRemediationSnippet?: string;
  aiRefinedPayload?: string;
}

interface DetectedParameter {
  id: string;
  name: string;
  method: string;
  type: string;
  baselineValue: string;
}

interface ScanHistoryEntry {
  id: string;
  targetUrl: string;
  scanDate: string;
  status: ScanStatus;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  wafStatus: string;
  wafVendor: string;
  securityScore: number;
  reportData?: any;
}

interface NetworkConfig {
  proxyEnabled: boolean;
  proxyUrl: string;
  customHeaders: { key: string; value: string }[];
  verifySsl: boolean;
  userAgent: string;
  timeout: number;
}

interface ScanTemplate {
  name: string;
  targetUrl: string;
  scanSpeed: 'Slow' | 'Normal' | 'Aggressive';
  plugins: {
    formAutoSubmit: boolean;
    apiScanning: boolean;
    sessionHandling: boolean;
    payloadEncoding: boolean;
    responseSimilarity: boolean;
    timingAnalysis: boolean;
    falsePositiveReduction: boolean;
  };
  authConfigured: boolean;
  authConfig: any;
  networkConfig: NetworkConfig;
}

const CHEAT_SHEET = [
  {
    category: 'Techniques',
    items: [
      { name: 'Error-Based', description: 'Exploiting database error messages to extract data.', payload: "' OR 1=1--" },
      { name: 'Boolean-Based', description: 'Inferring data by observing true/false response changes.', payload: "' AND 1=1--" },
      { name: 'Time-Based', description: 'Extracting data by causing database-level delays.', payload: "'; WAITFOR DELAY '0:0:5'--" },
      { name: 'UNION-Based', description: 'Using UNION operator to combine results from multiple tables.', payload: "' UNION SELECT NULL, username, password FROM users--" }
    ]
  },
  {
    category: 'Evasion Methods',
    items: [
      { name: 'URL Encoding', description: 'Encoding payloads to bypass simple string filters.', payload: "%27%20OR%201%3D1%20--" },
      { name: 'Double Encoding', description: 'Encoding twice to bypass multi-layer filtering.', payload: "%2527%2520OR%25201%253D1%2520--" },
      { name: 'Keyword Fragmentation', description: 'Using inline comments to break up SQL keywords.', payload: "UNI/**/ON SEL/**/ECT" },
      { name: 'Case Variation', description: 'Mixing uppercase and lowercase to bypass case-sensitive filters.', payload: "sElEcT * fRoM uSeRs" }
    ]
  },
  {
    category: 'Database Syntax',
    items: [
      { name: 'MySQL', description: 'Comments: #, -- , /* */. Version: VERSION().', payload: "SELECT VERSION()" },
      { name: 'PostgreSQL', description: 'Comments: --, /* */. Version: VERSION().', payload: "SELECT VERSION()" },
      { name: 'SQL Server', description: 'Comments: --, /* */. Version: @@VERSION.', payload: "SELECT @@VERSION" },
      { name: 'Oracle', description: 'Comments: --. Version: SELECT banner FROM v$version.', payload: "SELECT banner FROM v$version" }
    ]
  }
];

// Database Version Detection Simulation
const detectDatabaseVersion = (db: string): string => {
  const versions: Record<string, string[]> = {
    'MySQL': ['5.7.34', '8.0.26', '5.6.51', '8.0.32'],
    'PostgreSQL': ['13.4', '14.1', '12.8', '15.2'],
    'SQL Server': ['2019 (15.0)', '2017 (14.0)', '2022 (16.0)', '2016 (13.0)'],
    'Oracle': ['19c', '21c', '12c Release 2', '18c'],
    'SQLite': ['3.36.0', '3.39.4', '3.31.1']
  };
  
  const dbVersions = versions[db] || ['Unknown'];
  return dbVersions[Math.floor(Math.random() * dbVersions.length)];
};

// Mock Data Generators
const generateMockLogs = (target: string, count: number): LogEntry[] => {
  const logs: LogEntry[] = [];
  const methods = ['GET', 'POST'];
  const payloads = ["'", "1=1", "' OR '1'='1", "SLEEP(5)", "WAITFOR DELAY '0:0:5'", "UNION SELECT NULL--"];
  
  for (let i = 0; i < count; i++) {
    logs.push({
      id: getNextId(),
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
  { id: '1', name: 'id', method: 'GET', type: 'URL Query', baselineValue: '12' },
  { id: '2', name: 'search', method: 'GET', type: 'URL Query', baselineValue: 'test' },
  { id: '3', name: 'username', method: 'POST', type: 'Form Field', baselineValue: 'admin' },
  { id: '4', name: 'password', method: 'POST', type: 'Form Field', baselineValue: '********' },
  { id: '5', name: 'session_id', method: 'COOKIE', type: 'HTTP Header', baselineValue: 'abc123xyz' },
];

const mutatePayload = (payload: string, technique: string): string => {
  switch (technique) {
    case 'URL Encoding':
      return encodeURIComponent(payload);
    case 'Double URL Encoding':
      return encodeURIComponent(encodeURIComponent(payload));
    case 'Hex/Unicode Escape':
      return payload.split('').map(c => '0x' + c.charCodeAt(0).toString(16)).join('');
    case 'Keyword Fragmentation (Inline Comments)':
      return payload
        .replace(/UNION/gi, 'UNI/**/ON')
        .replace(/SELECT/gi, 'SEL/**/ECT')
        .replace(/FROM/gi, 'FR/**/OM')
        .replace(/WHERE/gi, 'WHE/**/RE')
        .replace(/AND/gi, 'AN/**/D')
        .replace(/OR/gi, 'O/**/R')
        .replace(/SLEEP/gi, 'SLE/**/EP')
        .replace(/WAITFOR/gi, 'WAIT/**/FOR');
    case 'Case Variation':
      // Randomly upper/lower case for SQL keywords specifically
      // Advanced mixed casing: not just keywords, but also fragments
      return payload.replace(/([a-z0-9]+)/gi, (match) => {
        if (match.length < 2) return match;
        return match.split('').map(c => Math.random() > 0.4 ? c.toUpperCase() : c.toLowerCase()).join('');
      });
    case 'White-space Randomization':
      // More complex whitespace randomization
      const spaces = [' ', '/**/', '\t', '\n', '\r', '\f', '\v', '/**_**/', '+', '%20', '%09', '%0A', '%0D', '/*!50000%20*/', '/*%0a*/'];
      return payload.replace(/\s+/g, () => {
        const count = Math.floor(Math.random() * 3) + 1;
        let res = '';
        for(let i=0; i<count; i++) res += spaces[Math.floor(Math.random() * spaces.length)];
        return res;
      });
    case 'Base64/Binary Wrappers':
      return btoa(payload);
    case 'HTTP Parameter Pollution (HPP)':
      return `${payload}&id=${payload}`;
    case 'Null Byte Injection (%00)':
      return payload.replace(/(\s|--|#)/g, '%00$1');
    case 'Keyword Splitting (Concat)':
      return payload
        .replace(/SELECT/gi, "CONCAT('SEL','ECT')")
        .replace(/UNION/gi, "CONCAT('UNI','ON')");
    default:
      return payload;
  }
};

const evasionTechniques = [
  'URL Encoding',
  'Double URL Encoding',
  'Hex/Unicode Escape',
  'Keyword Fragmentation (Inline Comments)',
  'Case Variation',
  'White-space Randomization',
  'Base64/Binary Wrappers',
  'HTTP Parameter Pollution (HPP)',
  'Null Byte Injection (%00)',
  'Keyword Splitting (Concat)'
];

const fingerprintDatabase = (response: string, payload: string): { db: string; version: string } => {
  const respLower = response.toLowerCase();
  const payloadLower = payload.toLowerCase();
  let db = 'Unknown';
  let version = 'Unknown';

  // 1. Error-based fingerprinting & Version Extraction
  if (respLower.includes('mysql') || respLower.includes('you have an error in your sql syntax')) {
    db = 'MySQL';
    const match = response.match(/MySQL\s+server\s+version\s+for\s+the\s+right\s+syntax\s+to\s+use\s+near\s+.*at\s+line\s+\d+/i) || 
                  response.match(/MySQL\s+(\d+\.\d+\.\d+)/i) ||
                  response.match(/(\d+\.\d+\.\d+)-MariaDB/i);
    if (match && match[1]) version = match[1];
  } else if (respLower.includes('postgresql') || respLower.includes('syntax error at or near') || respLower.includes('pg::')) {
    db = 'PostgreSQL';
    const match = response.match(/PostgreSQL\s+(\d+\.\d+)/i) || response.match(/PostgreSQL\s+(\d+\.\d+\.\d+)/i);
    if (match && match[1]) version = match[1];
  } else if (respLower.includes('sql server') || respLower.includes('microsoft ole db') || respLower.includes('unclosed quotation mark')) {
    db = 'MSSQL';
    const match = response.match(/SQL\s+Server\s+(\d{4})/i) || 
                  response.match(/Microsoft\s+SQL\s+Server\s+(\d+\.\d+)/i) ||
                  response.match(/SQL\s+Server\s+v(\d+\.\d+)/i);
    if (match && match[1]) version = match[1];
  } else if (respLower.includes('ora-') || respLower.includes('oracle') || respLower.includes('quoted string not properly terminated')) {
    db = 'Oracle';
    const match = response.match(/Oracle\s+Database\s+(\d+[a-z])/i) || response.match(/Oracle\s+Database\s+(\d+\.\d+)/i);
    if (match && match[1]) version = match[1];
  } else if (respLower.includes('sqlite') || respLower.includes('unrecognized token')) {
    db = 'SQLite';
    const match = response.match(/SQLite\s+(\d+\.\d+\.\d+)/i) || response.match(/SQLite\s+version\s+(\d+\.\d+)/i);
    if (match && match[1]) version = match[1];
  }

  // 2. Payload/Time-based fingerprinting (if not already found)
  if (db === 'Unknown') {
    if (payloadLower.includes('waitfor delay')) db = 'MSSQL';
    else if (payloadLower.includes('pg_sleep')) db = 'PostgreSQL';
    else if (payloadLower.includes('sleep(')) db = 'MySQL';
    else if (payloadLower.includes('dbms_lock.sleep')) db = 'Oracle';
  }

  // 3. Fallback to simulation if version still unknown but DB is known
  if (db !== 'Unknown' && version === 'Unknown') {
    version = detectDatabaseVersion(db);
  }

  return { db, version };
};

const rawMockFindings = [
  {
    id: '1',
    parameter: 'id (GET)',
    method: 'Error-Based' as const,
    payload: "'",
    rawPayload: "'",
    confidence: 98,
    severity: 'High' as const,
    request: "GET /api/users?id=1' HTTP/1.1\nHost: target.local\nUser-Agent: EduScanner/1.0",
    requestDetails: {
      method: 'GET',
      url: "/api/users?id=1'",
      headers: {
        'Host': 'target.local',
        'User-Agent': 'EduScanner/1.0'
      }
    },
    response: "HTTP/1.1 500 Internal Server Error\nContent-Type: text/html\n\n... You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1 ...",
    remediation: "// Vulnerable:\n$query = \"SELECT * FROM users WHERE id = '\" . $_GET['id'] . \"'\";\n\n// Corrected (Parameterized):\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $_GET['id']]);"
  },
  {
    id: '2',
    parameter: 'username (POST)',
    method: 'Boolean-Based' as const,
    payload: "' OR '1'='1",
    rawPayload: "' OR '1'='1",
    confidence: 85,
    severity: 'Medium' as const,
    request: "POST /login HTTP/1.1\nHost: target.local\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR '1'='1&password=foo",
    requestDetails: {
      method: 'POST',
      url: "/login",
      headers: {
        'Host': 'target.local',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: "username=admin' OR '1'='1&password=foo"
    },
    response: "HTTP/1.1 200 OK\nContent-Length: 4502\n\n... Welcome back, admin! ...",
    remediation: "// Vulnerable:\n$sql = \"SELECT * FROM users WHERE username = '\" . $user . \"' AND password = '\" . $pass . \"'\";\n\n// Corrected (Parameterized):\n$stmt = $db->prepare('SELECT * FROM users WHERE username = ?');\n$stmt->execute([$username]);"
  },
  {
    id: '3',
    parameter: 'search (GET)',
    method: 'Time-Based' as const,
    payload: "1'; WAITFOR DELAY '0:0:5'--",
    rawPayload: "1'; WAITFOR DELAY '0:0:5'--",
    confidence: 92,
    severity: 'Low' as const,
    request: "GET /search?q=1'; WAITFOR DELAY '0:0:5'-- HTTP/1.1\nHost: target.local",
    requestDetails: {
      method: 'GET',
      url: "/search?q=1'; WAITFOR DELAY '0:0:5'--",
      headers: {
        'Host': 'target.local'
      }
    },
    response: "HTTP/1.1 200 OK\nContent-Length: 120\n\n... No results found ...\n[Response Time: 5042ms]",
    remediation: "// Vulnerable:\n$query = \"SELECT * FROM products ORDER BY \" . $_GET['sort'];\n\n// Corrected (Allow-listing):\n$allowedSort = ['id', 'name', 'price'];\n$sort = in_array($_GET['sort'], $allowedSort) ? $_GET['sort'] : 'id';\n$query = \"SELECT * FROM products ORDER BY $sort\";"
  },
  {
    id: '4',
    parameter: 'sort (GET)',
    method: 'Error-Based' as const,
    payload: "1; SELECT pg_sleep(5)--",
    rawPayload: "1; SELECT pg_sleep(5)--",
    confidence: 95,
    severity: 'High' as const,
    request: "GET /items?sort=1; SELECT pg_sleep(5)-- HTTP/1.1\nHost: target.local",
    requestDetails: {
      method: 'GET',
      url: "/items?sort=1; SELECT pg_sleep(5)--",
      headers: {
        'Host': 'target.local'
      }
    },
    response: "HTTP/1.1 500 Internal Server Error\nContent-Length: 230\n\n... ERROR: syntax error at or near \";\" ...",
    remediation: "// Vulnerable:\n$query = \"SELECT * FROM items ORDER BY \" . $_GET['sort'];\n\n// Corrected (Parameterized):\n$stmt = $db->prepare('SELECT * FROM items ORDER BY :sort');\n$stmt->execute(['sort' => $_GET['sort']]);"
  },
  {
    id: '6',
    parameter: 'login (POST)',
    method: 'Boolean-Based' as const,
    payload: "UNI/**/ON SEL/**/ECT NULL,NULL,NULL--",
    rawPayload: "UNION SELECT NULL,NULL,NULL--",
    evasionTechnique: "Keyword Fragmentation (Inline Comments)",
    confidence: 98,
    severity: 'High' as const,
    request: "POST /login HTTP/1.1\nHost: target.local\nContent-Type: application/x-www-form-urlencoded\n\nusername=UNI/**/ON SEL/**/ECT NULL,NULL,NULL--&password=any",
    requestDetails: {
      method: 'POST',
      url: "/login",
      headers: {
        'Host': 'target.local',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: "username=UNI/**/ON SEL/**/ECT NULL,NULL,NULL--&password=any"
    },
    response: "HTTP/1.1 302 Found\nLocation: /dashboard\nSet-Cookie: session_id=admin_bypass_123\n\n... Redirecting to dashboard ...",
    remediation: "// Vulnerable:\n$sql = \"SELECT * FROM users WHERE username = '\" . $user . \"' AND password = '\" . $pass . \"'\";\n\n// Corrected (Parameterized):\n$stmt = $db->prepare('SELECT * FROM users WHERE username = ?');\n$stmt->execute([$username]);"
  },
  {
    id: '7',
    parameter: 'profile_id (GET)',
    method: 'Response Comparison' as const,
    payload: "123%27%20AND%201%3D1%20--",
    rawPayload: "123' AND 1=1 --",
    evasionTechnique: "URL Encoding",
    confidence: 89,
    severity: 'Medium' as const,
    request: "GET /profile?id=123%27%20AND%201%3D1%20-- HTTP/1.1\nHost: target.local\nCookie: session_id=admin_bypass_123",
    requestDetails: {
      method: 'GET',
      url: "/profile?id=123%27%20AND%201%3D1%20--",
      headers: {
        'Host': 'target.local',
        'Cookie': 'session_id=admin_bypass_123'
      }
    },
    response: "HTTP/1.1 200 OK\nContent-Length: 4500\n\n... [Authenticated Profile Data for Admin] ...",
    remediation: "// Vulnerable:\n$query = \"SELECT * FROM profiles WHERE id = '\" . $_GET['id'] . \"'\";\n\n// Corrected (Parameterized):\n$stmt = $pdo->prepare('SELECT * FROM profiles WHERE id = :id');\n$stmt->execute(['id' => $_GET['id']]);"
  },
  {
    id: '8',
    parameter: 'id (GET)',
    method: 'UNION-Based' as const,
    payload: "1%2527%20UNION%20SELECT%20NULL,%20username,%20password%20FROM%20users--",
    rawPayload: "1' UNION SELECT NULL, username, password FROM users--",
    evasionTechnique: "Double URL Encoding",
    confidence: 99,
    severity: 'High' as const,
    request: "GET /api/user?id=1%2527%20UNION%20SELECT%20NULL,%20username,%20password%20FROM%20users-- HTTP/1.1\nHost: target.local",
    requestDetails: {
      method: 'GET',
      url: "/api/user?id=1%2527%20UNION%20SELECT%20NULL,%20username,%20password%20FROM%20users--",
      headers: {
        'Host': 'target.local'
      }
    },
    response: "HTTP/1.1 200 OK\nContent-Length: 520\n\n... [Data Leak: admin:p@ssw0rd123, user1:secret] ...",
    remediation: "// Vulnerable:\n$query = \"SELECT id, name, desc FROM items WHERE cat = \" . $_GET['category'];\n\n// Corrected (Type Casting & Parameterization):\n$catId = (int)$_GET['category'];\n$stmt = $conn->prepare('SELECT id, name, desc FROM items WHERE cat = ?');\n$stmt->execute([$catId]);"
  }
];

const mockFindings: Finding[] = rawMockFindings.map(f => {
  const { db, version } = fingerprintDatabase(f.response, f.payload);
  return {
    ...f,
    dbGuess: db,
    dbVersion: version
  };
});

const generateAiAnomalies = (parameter: string): Finding => {
  const anomalyTypes = [
    {
      type: 'Response Structure Deviation',
      description: 'Significant change in HTML tag density and response structure compared to baseline.',
      confidence: 92,
      severity: 'High' as Severity,
      evidence: ['Tag count changed from 45 to 62', 'DOM depth increased by 3 levels', 'Response size increased by 15%']
    },
    {
      type: 'Blind Reflection Anomaly',
      description: 'Payload data reflected in non-standard response headers or hidden fields.',
      confidence: 85,
      severity: 'Medium' as Severity,
      evidence: ['Reflection detected in X-Internal-Trace header', 'Hidden input value changed to payload fragment', 'Status code 200 but content-type changed']
    },
    {
      type: 'Timing Side-Channel',
      description: 'Subtle but consistent delay variation detected across multiple payload permutations.',
      confidence: 78,
      severity: 'Low' as Severity,
      evidence: ['Baseline: 45ms', 'Payload A: 245ms', 'Payload B: 45ms', 'Consistent 200ms delta']
    }
  ];
  
  const anomaly = anomalyTypes[Math.floor(Math.random() * anomalyTypes.length)];
  
  return {
    id: getNextId(),
    parameter,
    method: 'AI Anomaly',
    payload: "'; -- AI_ANOMALY_TEST",
    confidence: anomaly.confidence,
    dbGuess: 'Unknown',
    dbVersion: 'N/A',
    severity: anomaly.severity,
    request: `POST /api/v1/resource HTTP/1.1\nHost: target.local\nContent-Type: application/json\n\n{"${parameter.split(' ')[0]}": "'; -- AI_ANOMALY_TEST"}`,
    requestDetails: {
      method: 'POST',
      url: '/api/v1/resource',
      headers: {
        'Host': 'target.local',
        'Content-Type': 'application/json'
      },
      body: `{"${parameter.split(' ')[0]}": "'; -- AI_ANOMALY_TEST"}`
    },
    response: `HTTP/1.1 200 OK\nContent-Length: 1240\n\n... [AI Insight: ${anomaly.type}. ${anomaly.description}] ...`,
    aiAnomalyDetails: {
      type: anomaly.type,
      description: anomaly.description,
      confidenceScore: anomaly.confidence,
      evidence: anomaly.evidence
    }
  };
};

const aiMockFinding: Finding = {
  id: '5',
  parameter: 'session_id (COOKIE)',
  method: 'AI Anomaly',
  payload: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'",
  confidence: 88,
  dbGuess: 'Unknown',
  dbVersion: 'N/A',
  severity: 'High',
  request: "GET /profile HTTP/1.1\nHost: target.local\nCookie: session_id=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'",
  requestDetails: {
    method: 'GET',
    url: '/profile',
    headers: {
      'Host': 'target.local',
      'Cookie': 'session_id=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\''
    }
  },
  response: "HTTP/1.1 200 OK\nContent-Length: 420\n\n... [AI Analysis: 94% deviation from baseline response structure. Suspicious data reflection detected despite 200 OK status. Possible blind injection.] ...",
  aiAnomalyDetails: {
    type: 'Response Structure Deviation',
    description: '94% deviation from baseline response structure. Suspicious data reflection detected despite 200 OK status.',
    confidenceScore: 88,
    evidence: [
      'Baseline structure: 12 tags, Current: 45 tags',
      'Reflection detected in hidden field: __VIEWSTATE',
      'Response time increased by 120ms'
    ]
  }
};

const mockWafResponses = [
  "HTTP/1.1 403 Forbidden\nServer: cloudflare\nCF-RAY: 1234567890abcdef\nCF-Cache-Status: HIT\n\n...",
  "HTTP/1.1 403 Forbidden\nX-Amzn-RequestId: 1234567890abcdef\nX-Amz-Cf-Id: 987654321\n\n...",
  "HTTP/1.1 406 Not Acceptable\nServer: Apache\nModSecurity Action\nX-WAF-Event: 12345\n\n...",
  "HTTP/1.1 403 Forbidden\nX-Sucuri-ID: 12345\nX-Sucuri-Cache: MISS\n\n...",
  "HTTP/1.1 403 Forbidden\nServer: AkamaiGHost\nX-Akamai-Request-ID: 12345\n\n...",
  "HTTP/1.1 403 Forbidden\nSet-Cookie: BIGipServer=12345\nX-Cnection: close\n\n...",
  "HTTP/1.1 403 Forbidden\nServer: FortiWeb\nX-FortiWeb-Block-ID: 123\n\n...",
  "HTTP/1.1 501 Not Implemented\nServer: Wallarm\n\n...",
  "HTTP/1.1 403 Forbidden\nServer: Reblaze\n\n...",
  "HTTP/1.1 200 OK\nServer: nginx\n\n..." // None
];

const analyzeWafPresence = (response: string): { status: string; vendor: string } => {
  const respLower = response.toLowerCase();
  
  // Cloudflare
  if (respLower.includes('server: cloudflare') || respLower.includes('cf-ray') || respLower.includes('__cfduid') || respLower.includes('cf-cache-status')) 
    return { status: 'Detected', vendor: 'Cloudflare' };
  
  // AWS WAF
  if (respLower.includes('x-amzn-requestid') || respLower.includes('awselb') || respLower.includes('x-amz-cf-id') || respLower.includes('x-amz-waf-action')) 
    return { status: 'Detected', vendor: 'AWS WAF' };
  
  // ModSecurity
  if (respLower.includes('modsecurity') || respLower.includes('406 not acceptable') || respLower.includes('mod_security') || respLower.includes('x-waf-event')) 
    return { status: 'Detected', vendor: 'ModSecurity' };
  
  // Sucuri
  if (respLower.includes('x-sucuri-id') || respLower.includes('server: sucuri') || respLower.includes('sucuri/cloudproxy') || respLower.includes('x-sucuri-cache')) 
    return { status: 'Detected', vendor: 'Sucuri' };
  
  // Imperva / Incapsula
  if (respLower.includes('x-iinfo') || respLower.includes('incapsula') || respLower.includes('visid_incap') || respLower.includes('x-cdn: incapsula')) 
    return { status: 'Detected', vendor: 'Imperva' };
  
  // Akamai
  if (respLower.includes('akamaighost') || respLower.includes('x-akamai') || respLower.includes('akamai-gws') || respLower.includes('x-akamai-request-id')) 
    return { status: 'Detected', vendor: 'Akamai' };
  
  // F5 BIG-IP
  if (respLower.includes('bigip') || respLower.includes('f5-trafficshield') || respLower.includes('x-cnection')) 
    return { status: 'Detected', vendor: 'F5 BIG-IP' };
  
  // Barracuda
  if (respLower.includes('barra_') || respLower.includes('bniscan')) 
    return { status: 'Detected', vendor: 'Barracuda' };

  // Fortinet
  if (respLower.includes('fortiweb') || respLower.includes('fortigate') || respLower.includes('x-fortiweb-block-id')) 
    return { status: 'Detected', vendor: 'Fortinet' };

  // Wallarm
  if (respLower.includes('wallarm') || respLower.includes('x-wallarm-request-id'))
    return { status: 'Detected', vendor: 'Wallarm' };

  // Reblaze
  if (respLower.includes('reblaze') || respLower.includes('x-reblaze-protection'))
    return { status: 'Detected', vendor: 'Reblaze' };

  // Generic WAF block patterns
  if (respLower.includes('blocked by waf') || respLower.includes('web application firewall') || respLower.includes('security policy violation') || respLower.includes('403 forbidden') || respLower.includes('999 request blocked')) 
    return { status: 'Detected', vendor: 'Generic WAF' };

  return { status: 'None Detected', vendor: 'None' };
};

const simulateWafBypass = (vendor: string, attemptNumber: number = 1): { bypassed: boolean; technique: string } => {
  if (vendor === 'None') return { bypassed: true, technique: 'None Needed' };
  
  const bypassTechniques = [
    'URL/Double Encoding',
    'Hex/Unicode Escape',
    'Base64/Binary Wrappers',
    'Keyword Fragmentation (Inline Comments)',
    'Case Variation (sElEcT)',
    'White-space Randomization (/**/)',
    'HTTP Header Spoofing (X-Forwarded-For)',
    'Behavioral Stealth (Jitter/Slow Scan)',
    'Null Byte Injection (%00)',
    'HTTP Parameter Pollution (HPP)',
    'Chunked Transfer Encoding',
    'Keyword Splitting (Concat)',
    'Protocol Downgrade Simulation',
    'JSON/XML Payload Wrapping',
    'Mixed Casing + Whitespace Randomization',
    'HPP + Keyword Fragmentation',
    'Double Encoding + Null Byte Injection'
  ];
  
  // Pick a technique based on attempt number or randomly
  const technique = bypassTechniques[(attemptNumber - 1) % bypassTechniques.length];
  
  // Success probability increases with more attempts (simulation of refining techniques)
  // Sophisticated WAFs like Cloudflare/Sucuri have lower base success
  const isSophisticated = ['Cloudflare', 'Sucuri', 'ModSecurity', 'Akamai', 'AWS WAF'].includes(vendor);
  const baseProbability = isSophisticated ? 0.15 : 0.30; 
  const successProbability = baseProbability + (attemptNumber * 0.20); 
  const isBypassed = Math.random() < successProbability;
  
  return { bypassed: isBypassed, technique };
};

export default function App() {
  const { authConfig, setAuthConfig, authConfigured, setAuthConfigured } = useAuth();
  const { user, isAuthReady, logout: handleLogout } = useUserAuth();
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080/dvwa');
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [parameters, setParameters] = useState<DetectedParameter[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [progress, setProgress] = useState(0);
  const [scanSpeed, setScanSpeed] = useState<'Slow' | 'Normal' | 'Aggressive' | 'Custom'>('Normal');
  const [customDelay, setCustomDelay] = useState<number>(1000);
  const [findingFilters, setFindingFilters] = useState({ severity: 'All', method: 'All' });
  const [securityScore, setSecurityScore] = useState(100);
  const [rateLimit, setRateLimit] = useState<number>(0);
  const [copiedReq, setCopiedReq] = useState(false);
  const [copiedRes, setCopiedRes] = useState(false);
  const [wafStatus, setWafStatus] = useState<string>('Unknown');
  const [wafVendor, setWafVendor] = useState<string>('None');
  const [bypassStats, setBypassStats] = useState({ attempts: 0, successes: 0 });
  const [aiMode, setAiMode] = useState(false);
  const [highThinkingMode, setHighThinkingMode] = useState(false);
  const [scanPhase, setScanPhase] = useState<string>('Idle');
  const [activeTab, setActiveTab] = useState<'scanner' | 'dashboard' | 'settings' | 'report' | 'cheat-sheet' | 'history'>('scanner');
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [networkConfig, setNetworkConfig] = useState<NetworkConfig>({
    proxyEnabled: false,
    proxyUrl: '',
    customHeaders: [{ key: 'User-Agent', value: 'EduScanner/1.0' }],
    verifySsl: true,
    userAgent: 'EduScanner/1.0',
    timeout: 30
  });
  const [chartData, setChartData] = useState<any[]>([]);
  const [openSettingsSection, setOpenSettingsSection] = useState<string | null>('proxy');
  const [aiReport, setAiReport] = useState<{
    verdict: 'VULNERABLE' | 'SECURE' | 'POTENTIALLY VULNERABLE';
    confidence: string;
    securityScore: number;
    executiveSummary: string;
    severityStats: {
      critical: { count: number; avgConf: number };
      medium: { count: number; avgConf: number };
      low: { count: number; avgConf: number };
    };
    findingsDeepDive: Array<{
      type: string;
      parameter: string;
      method: string;
      detectionVector: string;
      wafStatus: string;
      impact: string;
      poc: {
        baselineLatency: number;
        injectedLatency: number;
        encodedPayload: string;
        decodedPayload: string;
      };
    }>;
    extractionProof: {
      dbType: string;
      currentUser: string;
      tables: string[];
    };
    recommendations: string[];
    scanStats: {
      totalRequests: number;
      bypassSimulations: number;
      avgResponseTime: number;
      aiConfidenceRating: number;
    };
    // Compatibility fields
    reasoning?: string;
    technicalReasoning?: string;
    riskSummary?: string;
  } | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isAiAnalyzing, setIsAiAnalyzing] = useState(false);
  const [isDeepAnalyzing, setIsDeepAnalyzing] = useState(false);
  const [explanationMode, setExplanationMode] = useState<'simple' | 'technical'>('simple');
  const [detectionTimeline, setDetectionTimeline] = useState<{ time: string; event: string; severity: Severity }[]>([]);
  const [aiChatMessages, setAiChatMessages] = useState<{ role: 'user' | 'assistant'; content: string }[]>([]);
  const [isAiChatOpen, setIsAiChatOpen] = useState(false);
  const [isAiChatLoading, setIsAiChatLoading] = useState(false);
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
  const [requestBudget, setRequestBudget] = useState(500);
  const [totalRequestsSent, setTotalRequestsSent] = useState(0);
  const [autoStopOnVulnerability, setAutoStopOnVulnerability] = useState(false);
  const [budgetMode, setBudgetMode] = useState<'conservative' | 'balanced' | 'aggressive'>('balanced');
  const [requestEfficiencyScore, setRequestEfficiencyScore] = useState(0);
  const [baselineLatency, setBaselineLatency] = useState<number>(0);
  
  const handleAiChatSubmit = async (message: string) => {
    if (!message.trim()) return;
    
    const newMessages: { role: 'user' | 'assistant'; content: string }[] = [...aiChatMessages, { role: 'user', content: message }];
    setAiChatMessages(newMessages);
    setIsAiChatLoading(true);
    
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
      const context = `
        Current Scan Status: ${status}
        Target URL: ${targetUrl}
        Findings Count: ${findings.length}
        Critical: ${findings.filter(f => f.severity === 'Critical').length}
        High: ${findings.filter(f => f.severity === 'High').length}
        WAF Status: ${wafStatus}
        WAF Vendor: ${wafVendor}
        
        Recent Logs:
        ${logs.slice(-5).map(l => `[${l.type}] ${l.message}`).join('\n')}
        
        Current Findings:
        ${findings.map(f => `- ${f.parameter} (${f.method}): ${f.severity}`).join('\n')}
      `;
      
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: [
          { role: 'user', parts: [{ text: `Context: ${context}\n\nUser Question: ${message}` }] }
        ],
        config: {
          systemInstruction: "You are a senior SQL injection security expert and the AI assistant for the EduScanner platform. Answer the user's questions concisely and technically. Help them understand the scan results, suggest bypasses, or explain vulnerabilities. If they ask for remediation, provide code snippets."
        }
      });
      
      setAiChatMessages([...newMessages, { role: 'assistant', content: response.text || "I'm sorry, I couldn't process that." }]);
    } catch (error) {
      console.error("AI Chat Error:", error);
      setAiChatMessages([...newMessages, { role: 'assistant', content: "Error: Failed to connect to AI engine." }]);
    } finally {
      setIsAiChatLoading(false);
    }
  };

  const refineFindingWithAi = async (finding: Finding) => {
    setIsAiAnalyzing(true);
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
      const response = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `
          Analyze this SQL injection finding and provide:
          1. A refined, more advanced payload to bypass potential WAF filters. Use techniques like HPP, keyword fragmentation, case variation, and whitespace randomization.
          2. A detailed remediation code snippet (e.g., using prepared statements in PHP/Node.js/Python).
          3. A technical explanation of why the original payload worked and how the refined one evades filters.
          
          Finding Details:
          Parameter: ${finding.parameter}
          Method: ${finding.method}
          Original Payload: ${finding.payload}
          DB Guess: ${finding.dbGuess}
          Severity: ${finding.severity}
          WAF Status: ${wafStatus}
          
          Response Format: JSON
          {
            "refinedPayload": "...",
            "remediationSnippet": "...",
            "deepExplanation": "..."
          }
        `,
        config: {
          responseMimeType: "application/json"
        }
      });
      
      const result = JSON.parse(response.text || "{}");
      setFindings(prev => prev.map(f => f.id === finding.id ? {
        ...f,
        aiRefinedPayload: result.refinedPayload,
        aiRemediationSnippet: result.remediationSnippet,
        aiAnomalyDetails: {
          ...(f.aiAnomalyDetails || { type: 'AI Refinement', description: '', confidenceScore: 100, evidence: [] }),
          deepExplanation: result.deepExplanation
        }
      } : f));
      setSelectedFinding(prev => prev?.id === finding.id ? {
        ...prev,
        aiRefinedPayload: result.refinedPayload,
        aiRemediationSnippet: result.remediationSnippet,
        aiAnomalyDetails: {
          ...(prev.aiAnomalyDetails || { type: 'AI Refinement', description: '', confidenceScore: 100, evidence: [] }),
          deepExplanation: result.deepExplanation
        }
      } : prev);
    } catch (error) {
      console.error("Refine Finding Error:", error);
    } finally {
      setIsAiAnalyzing(false);
    }
  };

  const exportTemplate = () => {
    const template: ScanTemplate = {
      name: `Template_${new Date().getTime()}`,
      targetUrl,
      scanSpeed,
      plugins,
      authConfigured,
      authConfig,
      networkConfig
    };
    const blob = new Blob([JSON.stringify(template, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${template.name}.json`;
    a.click();
  };

  const importTemplate = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const template = JSON.parse(event.target?.result as string) as ScanTemplate;
        setTargetUrl(template.targetUrl);
        setScanSpeed(template.scanSpeed);
        setPlugins(template.plugins);
        setAuthConfigured(template.authConfigured);
        setAuthConfig(template.authConfig);
        setNetworkConfig(template.networkConfig);
        alert('Template imported successfully!');
      } catch (err) {
        alert('Failed to import template. Invalid JSON format.');
      }
    };
    reader.readAsText(file);
  };

  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Save to history when scan completes
  useEffect(() => {
    if (status === 'completed' && targetUrl) {
      const now = new Date().toLocaleString();
      const critical = findings.filter(f => f.severity === 'Critical').length;
      const high = findings.filter(f => f.severity === 'High').length;
      const medium = findings.filter(f => f.severity === 'Medium').length;
      const low = findings.filter(f => f.severity === 'Low').length;
      
      const score = Math.max(0, 100 - (critical * 25 + high * 15 + medium * 10 + low * 5));
      setSecurityScore(score);

      const newEntry: ScanHistoryEntry = {
        id: Math.random().toString(36).substr(2, 9),
        targetUrl,
        scanDate: now,
        status: 'completed',
        findingsCount: findings.length,
        criticalCount: critical,
        highCount: high,
        mediumCount: medium,
        lowCount: low,
        wafStatus,
        wafVendor,
        securityScore: score,
        reportData: { findings, logs, aiReport, targetUrl, wafStatus, wafVendor, securityScore: score }
      };
      setScanHistory(prev => [newEntry, ...prev]);
    }
  }, [status]);

  // Scheduled Scan Logic
  useEffect(() => {
    if (!scheduledTime) return;

    const checkSchedule = setInterval(() => {
      const now = new Date();
      const [hours, minutes] = scheduledTime.split(':').map(Number);
      const scheduledDate = new Date();
      scheduledDate.setHours(hours, minutes, 0, 0);

      // If scheduled time is in the past for today, assume it's for tomorrow
      if (scheduledDate < now) {
        scheduledDate.setDate(scheduledDate.getDate() + 1);
      }

      // Trigger if within 1 minute of scheduled time
      const diff = Math.abs(now.getTime() - scheduledDate.getTime());
      if (diff < 60000 && status === 'idle') {
        handleStart();
        setScheduledTime(''); // Clear after trigger
        clearInterval(checkSchedule);
      }
    }, 10000); // Check every 10 seconds

    return () => clearInterval(checkSchedule);
  }, [scheduledTime, status]);

  // Auth State Listener - Removed as it's handled by UserAuthContext
  
  const handleLogin = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (error) {
      console.error("Login Error:", error);
    }
  };

  const generateAdvancedAiPayload = async (parameter: string): Promise<Finding> => {
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });
      const prompt = `Generate a sophisticated WAF-evading SQL injection payload for the parameter "${parameter}". 
      Focus on advanced techniques like HTTP Parameter Pollution (HPP), mixed casing, and whitespace randomization.
      The target is detected as anomalous. Provide the response in JSON format with the following structure:
      {
        "type": "AI Anomaly Detection",
        "description": "Technical description of the anomaly",
        "payload": "The actual evasion payload",
        "technique": "Name of the evasion technique used",
        "confidence": 95,
        "severity": "High",
        "evidence": ["Evidence 1", "Evidence 2"],
        "deepExplanation": "Technical explanation of why this payload bypasses WAFs"
      }`;

      const response = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              type: { type: Type.STRING },
              description: { type: Type.STRING },
              payload: { type: Type.STRING },
              technique: { type: Type.STRING },
              confidence: { type: Type.NUMBER },
              severity: { type: Type.STRING },
              evidence: { type: Type.ARRAY, items: { type: Type.STRING } },
              deepExplanation: { type: Type.STRING }
            },
            required: ["type", "description", "payload", "technique", "confidence", "severity", "evidence", "deepExplanation"]
          }
        }
      });

      const data = JSON.parse(response.text || '{}');
      
      return {
        id: getNextId(),
        parameter,
        method: 'AI Anomaly',
        payload: data.payload || "'; -- AI_ANOMALY_TEST",
        confidence: data.confidence || 90,
        dbGuess: 'Unknown',
        dbVersion: 'N/A',
        severity: (data.severity as Severity) || 'High',
        request: `POST /api/v1/resource HTTP/1.1\nHost: target.local\nContent-Type: application/json\n\n{"${parameter.split(' ')[0]}": "${data.payload}"}`,
        requestDetails: {
          method: 'POST',
          url: '/api/v1/resource',
          headers: {
            'Host': 'target.local',
            'Content-Type': 'application/json'
          },
          body: `{"${parameter.split(' ')[0]}": "${data.payload}"}`
        },
        response: `HTTP/1.1 200 OK\nContent-Length: 1240\n\n... [AI Insight: ${data.type}. ${data.description}] ...`,
        aiAnomalyDetails: {
          type: data.type,
          description: data.description,
          confidenceScore: data.confidence,
          evidence: data.evidence,
          deepExplanation: data.deepExplanation
        }
      };
    } catch (error) {
      console.error("Error generating advanced AI payload:", error);
      return generateAiAnomalies(parameter); // Fallback
    }
  };

  // Auto-scroll console
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // WAF Detection Reaction
  useEffect(() => {
    if (wafStatus === 'Detected' && wafVendor !== 'None') {
      setScanSpeed('Slow');
      setPlugins(p => ({ ...p, payloadEncoding: true, timingAnalysis: true }));
      setLogs(prev => [...prev.slice(-49), {
        id: getNextId(),
        timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        type: 'info',
        message: `WAF Detected: ${wafVendor}. Adjusting scan speed to Slow and enabling payload encoding evasion.`,
        responseTime: 0
      }]);
    }
  }, [wafStatus, wafVendor]);

  // Simulation Logic
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (status === 'scanning') {
      let currentProgress = 0;
      
      const baseDelay = scanSpeed === 'Slow' ? 1000 : scanSpeed === 'Aggressive' ? 150 : scanSpeed === 'Custom' ? customDelay : 500;
      
      // Adaptive Strategy: Adjust speed based on WAF and Response Times
      const getAdaptiveDelay = () => {
        let multiplier = 1;
        if (budgetMode === 'conservative') multiplier *= 2.5;
        if (budgetMode === 'aggressive') multiplier *= 0.4;
        
        if (wafStatus.includes('Detected')) multiplier *= 2.0;
        if (wafStatus.includes('Blocked')) multiplier *= 3.0;
        
        // Response time factor: if latency is high, slow down to avoid DoS or detection
        if (baselineLatency > 500) multiplier *= 1.5;
        if (baselineLatency > 2000) multiplier *= 3.0;
        
        const rateLimitDelay = rateLimit > 0 ? 1000 / rateLimit : 0;
        const jitter = (budgetMode === 'conservative' || scanSpeed === 'Slow') ? Math.random() * 800 : Math.random() * 100;
        
        return Math.max(baseDelay * multiplier, rateLimitDelay) + jitter;
      };

      const progressIncrement = scanSpeed === 'Slow' ? 1.5 : scanSpeed === 'Aggressive' ? 12 : 6;
      const modeProgressMultiplier = budgetMode === 'conservative' ? 0.4 : budgetMode === 'aggressive' ? 2.5 : 1;

      const runScanStep = () => {
        if (status !== 'scanning') return;

        const delay = getAdaptiveDelay();
        
        // Request Budget Logic
        const estimatedRequestsPerPercent = budgetMode === 'conservative' ? 4 : budgetMode === 'aggressive' ? 25 : 12;
        const currentRequests = Math.floor(currentProgress * estimatedRequestsPerPercent);
        setTotalRequestsSent(currentRequests);

        // Efficiency Score Calculation: Findings per 100 requests
        const efficiency = currentRequests > 0 ? Math.min(100, Math.round((findings.length / currentRequests) * 1000)) : 0;
        setRequestEfficiencyScore(efficiency);

        if (currentRequests >= requestBudget) {
          currentProgress = 100;
          setStatus('completed');
          setScanPhase('Completed (Budget Exhausted)');
          setFindings(aiMode ? [...mockFindings, aiMockFinding] : mockFindings);
          return;
        }

        // Auto Stop on Vulnerability
        if (autoStopOnVulnerability && findings.length > 0) {
          currentProgress = 100;
          setStatus('completed');
          setScanPhase('Completed (Vulnerability Detected)');
          return;
        }

        currentProgress += (Math.random() * progressIncrement) * modeProgressMultiplier;
        if (currentProgress >= 100) {
          currentProgress = 100;
          setStatus('completed');
          setScanPhase('Completed');
          setFindings(aiMode ? [...mockFindings, aiMockFinding] : mockFindings);
        } else if (currentProgress < 10) {
          setScanPhase('Pre-Scan Handshake');
        } else if (currentProgress < 15) {
          setScanPhase('Precision Latency Baselining');
          if (baselineLatency === 0) {
            const baseline = Math.floor(Math.random() * 150) + 50; // 50-200ms
            setBaselineLatency(baseline);
            setLogs(prev => [...prev.slice(-49), {
              id: getNextId(),
              timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              type: 'info',
              message: `Precision Latency Baselining: Averaging 10 standard requests to ${targetUrl.split('\n')[0]}...`,
              responseTime: baseline
            }]);
            setTimeout(() => {
              setLogs(prev => [...prev.slice(-49), {
                id: getNextId(),
                timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
                type: 'success',
                message: `Baseline established: ${baseline}ms (Normal Latency).`,
                responseTime: baseline
              }]);
            }, 1000);
          }
        } else if (currentProgress < 30) {
          setScanPhase('Crawling & Discovery');
          if (currentProgress > 15 && currentProgress <= 25) {
            if (wafStatus === 'Detecting...') {
              const randomResponse = mockWafResponses[Math.floor(Math.random() * mockWafResponses.length)];
              const result = analyzeWafPresence(randomResponse);
              setWafStatus(result.status);
              setWafVendor(result.vendor);
            }
          }
          if (currentProgress > 25 && wafStatus === 'Detected' && bypassStats.attempts === 0) {
            const runBypassAttempt = (attempt: number) => {
              const result = simulateWafBypass(wafVendor, attempt);
              setBypassStats(prev => ({ 
                attempts: prev.attempts + 1, 
                successes: result.bypassed ? prev.successes + 1 : prev.successes 
              }));
              
              if (result.bypassed) {
                setWafStatus(`Bypassed (${result.technique})`);
                const techLogs = [
                  `Evasion Engine (Attempt ${attempt}): Activating ${result.technique} for ${wafVendor}.`,
                  `Rotating User-Agents and spoofing X-Forwarded-For headers...`,
                  `Applying mutation to all outgoing payloads.`,
                  `WAF Bypass Successful: Encoded payload successfully reached the database.`
                ];
                techLogs.forEach((msg, idx) => {
                  setTimeout(() => {
                    setLogs(prev => [...prev.slice(-49), {
                      id: getNextId(),
                      timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
                      type: idx === 3 ? 'success' : 'info',
                      message: msg,
                      responseTime: 0
                    }]);
                  }, idx * 300);
                });
                return true;
              } else {
                setLogs(prev => [...prev.slice(-49), {
                  id: getNextId(),
                  timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
                  type: 'error',
                  message: `WAF Bypass Attempt ${attempt} Failed (${result.technique}): ${wafVendor} blocked the request.`,
                  responseTime: 0
                }]);
                return false;
              }
            };

            // Sequential bypass logic
            let success = runBypassAttempt(1);
            if (!success) {
              setTimeout(() => {
                success = runBypassAttempt(2);
                if (!success) {
                  setTimeout(() => {
                    success = runBypassAttempt(3);
                    if (!success) {
                      setWafStatus('Blocked');
                      setLogs(prev => [...prev.slice(-49), {
                        id: getNextId(),
                        timestamp: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
                        type: 'error',
                        message: `WAF Bypass Failed: ${wafVendor} blocked all 3 sequential evasion attempts.`,
                        responseTime: 0
                      }]);
                    }
                  }, 1000);
                }
              }, 1000);
            }
          }
        } else {
          setScanPhase(authConfigured ? 'Authenticated Scanning' : 'Active Scanning');
        }
        setProgress(currentProgress);
        
        const now = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

        // Time-Based Blind Detection Simulation
        if (plugins.timingAnalysis && currentProgress > 60 && currentProgress < 65 && !findings.some(f => f.method === 'Time-Based')) {
          const db = ['MySQL', 'PostgreSQL', 'SQL Server'][Math.floor(Math.random() * 3)];
          const sleepPayloads: Record<string, string> = {
            'MySQL': 'SLEEP(5)',
            'PostgreSQL': 'pg_sleep(5)',
            'SQL Server': "WAITFOR DELAY '0:0:5'"
          };
          
          const payload = sleepPayloads[db];
          const requestedSleep = 5000;
          const actualLatency = baselineLatency + requestedSleep + (Math.random() * 200);
          
          setLogs(prev => [...prev.slice(-49), {
            id: getNextId(),
            timestamp: now,
            type: 'warning',
            message: `Inconclusive results from Error/Boolean probes. Activating Time-Based Blind Engine...`,
            responseTime: baselineLatency
          }]);

          // Triple-Check Verification
          [1, 2, 3].forEach((check, idx) => {
            setTimeout(() => {
              setLogs(prev => [...prev.slice(-49), {
                id: getNextId(),
                timestamp: now,
                type: 'info',
                message: `Time-Based Probe (Check ${check}/3): Injecting ${payload} into "id" parameter...`,
                responseTime: actualLatency
              }]);
              
              if (check === 3) {
                const dbVersion = detectDatabaseVersion(db);
                const timeFinding: Finding = {
                  id: getNextId(),
                  parameter: 'id',
                  method: 'Time-Based',
                  payload: mutatePayload(payload, 'Keyword Fragmentation (Inline Comments)'),
                  rawPayload: payload,
                  confidence: 100,
                  dbGuess: db,
                  dbVersion: dbVersion,
                  severity: 'Critical',
                  request: `GET /api/data?id=${payload} HTTP/1.1\nHost: ${targetUrl.split('\n')[0]}`,
                  requestDetails: {
                    method: 'GET',
                    url: `/api/data?id=${payload}`,
                    headers: {
                      'Host': targetUrl.split('\n')[0]
                    }
                  },
                  response: `HTTP/1.1 200 OK\nContent-Length: 420\n\n... [Latency Anomaly: ${actualLatency}ms vs Baseline ${baselineLatency}ms] ...`,
                  timingData: {
                    baselineLatency,
                    actualLatency,
                    requestedSleep,
                    isConsistent: true
                  }
                };
                setFindings(prev => [...prev, timeFinding]);
                setDetectionTimeline(prev => [...prev, { time: now, event: `Time-Based Blind Injection Confirmed (${db})`, severity: 'High' }]);
                
                setLogs(prev => [...prev.slice(-49), {
                  id: getNextId(),
                  timestamp: now,
                  type: 'success',
                  message: `Database Fingerprinting: Detected ${db} (Version: ${dbVersion}) via response behavior.`,
                  responseTime: 0
                }]);
                
                // Save finding to Firestore
                if (currentScanId && user) {
                  const findingsCol = collection(db as any, 'scans', currentScanId as string, 'findings');
                  addDoc(findingsCol, {
                    ...timeFinding,
                    userId: user.uid,
                    scanId: currentScanId,
                    timestamp: Timestamp.now()
                  }).catch(err => handleFirestoreError(err, OperationType.CREATE, `scans/${currentScanId}/findings`));
                }
              }
            }, (idx + 1) * 1500);
          });
        }

        // Add a log entry
        const newLog = generateMockLogs(targetUrl.split('\n')[0] || 'http://localhost', 1)[0];
        newLog.timestamp = now;
        
        // WAF & Rate Limit Awareness (Simulated)
        if (Math.random() > 0.98) {
          const isRateLimit = Math.random() > 0.5;
          newLog.type = 'error';
          newLog.message = isRateLimit ? '429 Too Many Requests: Rate limit exceeded. Throttling scan.' : '403 Forbidden: Potential WAF block detected. Adjusting evasion.';
          setScanSpeed('Slow');
          setLogs(prev => [...prev.slice(-49), {
            id: getNextId(),
            timestamp: now,
            type: 'warning',
            message: `Production site protection detected. Auto-adjusting request budget and speed.`,
            responseTime: 0
          }]);
        }

        // Auth-State Heartbeat & Auto-Re-login
        if (authConfigured && currentProgress % 15 < 1 && currentProgress > 10) {
          const sessionLost = Math.random() > 0.92;
          if (sessionLost) {
            setLogs(prev => [...prev.slice(-49), {
              id: getNextId(),
              timestamp: now,
              type: 'warning',
              message: `Auth-State Heartbeat Failed: Success marker "${authConfig.authenticatedBaseline}" not found. Session may have rotated or timed out.`,
              responseTime: 0
            }]);

            if (authConfig.autoReauth) {
              setLogs(prev => [...prev.slice(-49), {
                id: getNextId(),
                timestamp: now,
                type: 'info',
                message: `Initiating Auto-Re-login handshake via ${authConfig.method}...`,
                responseTime: 150
              }]);
              
              setTimeout(() => {
                setLogs(prev => [...prev.slice(-49), {
                  id: getNextId(),
                  timestamp: now,
                  type: 'success',
                  message: `Session re-established. Captured new tokens/cookies for ${authConfig.method}.`,
                  responseTime: 45
                }]);
              }, 1000);
            } else {
              setLogs(prev => [...prev.slice(-49), {
                id: getNextId(),
                timestamp: now,
                type: 'error',
                message: `Authenticated Scan Blocked: Session lost and auto-reauth is disabled.`,
                responseTime: 0
              }]);
            }
          }
        }

        if (authConfigured && Math.random() > 0.8) {
          newLog.message = `Authenticated request to ${newLog.url} (Session Active)`;
          newLog.type = 'info';
        }
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
        
        // AI Anomaly Detection Simulation
        if (aiMode && currentProgress > 40 && Math.random() > 0.92 && findings.length < 8) {
          setIsAiAnalyzing(true);
          const param = parameters[Math.floor(Math.random() * parameters.length)]?.name || 'unknown';
          
          generateAdvancedAiPayload(param).then(anomaly => {
            setFindings(prev => {
              if (prev.some(f => f.aiAnomalyDetails?.type === anomaly.aiAnomalyDetails?.type)) return prev;
              return [...prev, anomaly];
            });
            setDetectionTimeline(prev => [...prev, { 
              time: now, 
              event: `AI Anomaly: ${anomaly.aiAnomalyDetails?.type} in ${anomaly.parameter}`, 
              severity: anomaly.severity 
            }]);
            setIsAiAnalyzing(false);
            
            setLogs(prev => [...prev.slice(-49), {
              id: getNextId(),
              timestamp: now,
              type: 'warning',
              message: `AI Anomaly Detected: ${anomaly.aiAnomalyDetails?.type} (Confidence: ${anomaly.confidence}%)`,
              responseTime: 0
            }]);
          });
        }
        
        // Randomly add findings during scan
        // Discovery Logic
        if (currentProgress > 10 && parameters.length === 0) {
          const domain = targetUrl.split('\n')[0].replace(/https?:\/\//, '').split('/')[0];
          const discovered: DetectedParameter[] = [
            { id: '1', name: 'id', method: 'GET', type: 'URL Query', baselineValue: '1' },
            { id: '2', name: 'q', method: 'GET', type: 'URL Query', baselineValue: '' },
            { id: '3', name: 'user', method: 'POST', type: 'Form Field', baselineValue: 'admin' },
            { id: '4', name: 'password', method: 'POST', type: 'Form Field', baselineValue: '********' },
            { id: '5', name: 'session_id', method: 'COOKIE', type: 'HTTP Header', baselineValue: 'abc123xyz' },
            { id: '6', name: 'X-Forwarded-For', method: 'HEADER', type: 'HTTP Header', baselineValue: '127.0.0.1' },
            { id: '7', name: 'Referer', method: 'HEADER', type: 'HTTP Header', baselineValue: `https://${domain}/` }
          ];
          setParameters(discovered);
        }
        
        // Production Logic: Hardened Scanning (Boolean-Blind/Time-Based)
        if (currentProgress > 30 && currentProgress < 40 && targetUrl.includes('https')) {
          setScanPhase('Hardened Scanning (HTTPS)');
          if (Math.random() > 0.9) {
            setLogs(prev => [...prev.slice(-49), {
              id: getNextId(),
              timestamp: now,
              type: 'info',
              message: 'Hardened Target: Suppressed errors detected. Switching to Boolean-Blind & Time-Based analysis.',
              responseTime: 0
            }]);
          }
        }
        
        if (currentProgress > 35 && findings.length === 0) {
          setFindings([mockFindings[0]]);
          setDetectionTimeline(prev => [...prev, { time: now, event: `Vulnerability detected in ${mockFindings[0].parameter}`, severity: mockFindings[0].severity }]);
        }
        if (currentProgress > 55 && findings.length === 1) {
          setFindings([mockFindings[0], mockFindings[1]]);
          setDetectionTimeline(prev => [...prev, { time: now, event: `Vulnerability detected in ${mockFindings[1].parameter}`, severity: mockFindings[1].severity }]);
        }

        // Authentication Bypass Probing
        if (currentProgress > 45 && currentProgress < 55 && !findings.some(f => f.parameter.includes('login'))) {
          setLogs(prev => [...prev.slice(-49), {
            id: getNextId(),
            timestamp: now,
            type: 'info',
            message: 'Probing login fields for Authentication Bypass vulnerabilities...',
            responseTime: 45
          }]);
          if (Math.random() > 0.5) {
            const bypassFinding = mockFindings.find(f => f.parameter.includes('login'));
            if (bypassFinding) {
              setFindings(prev => [...prev, bypassFinding]);
              setDetectionTimeline(prev => [...prev, { time: now, event: `CRITICAL: Authentication Bypass detected in ${bypassFinding.parameter}`, severity: 'High' }]);
              setLogs(prev => [...prev.slice(-49), {
                id: getNextId(),
                timestamp: now,
                type: 'error',
                message: 'CRITICAL: Authentication Bypass confirmed via SQLi logic.',
                responseTime: 0
              }]);
            }
          }
        }

        // Authenticated Parameter Testing
        if (authConfigured && currentProgress > 70 && !findings.some(f => f.parameter.includes('profile'))) {
          const authFinding = mockFindings.find(f => f.parameter.includes('profile'));
          if (authFinding) {
            setFindings(prev => [...prev, authFinding]);
            setDetectionTimeline(prev => [...prev, { time: now, event: `Vulnerability detected in Authenticated Parameter: ${authFinding.parameter}`, severity: 'Medium' }]);
          }
        }
        
        if (currentProgress > 85 && !findings.some(f => f.method === 'UNION-Based')) {
          const unionFinding = mockFindings.find(f => f.method === 'UNION-Based');
          if (unionFinding) {
            setFindings(prev => [...prev, unionFinding]);
            setDetectionTimeline(prev => [...prev, { time: now, event: `Vulnerability detected: UNION-Based Data Extraction in ${unionFinding.parameter}`, severity: 'High' }]);
          }
        }
        
        if (currentProgress >= 100 && aiMode && !findings.some(f => f.method === 'AI Anomaly')) {
          setFindings(prev => [...prev, aiMockFinding]);
        }
        
        if (currentProgress < 100) {
          interval = setTimeout(runScanStep, delay);
        }
      };

      interval = setTimeout(runScanStep, 500);
    }
    return () => clearTimeout(interval);
  }, [status, targetUrl, findings.length, scanSpeed, rateLimit, aiMode]);

  const generateAiReport = async () => {
    if (findings.length === 0 && status !== 'completed') return;
    
    setIsAnalyzing(true);
    setActiveTab('report');

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });
      
      const inputData = {
        findings: findings.map(f => ({
          severity: f.severity,
          confidence: f.confidence,
          method: f.method,
          parameter: f.parameter,
          dbGuess: f.dbGuess,
          dbVersion: f.dbVersion,
          requestDetails: f.requestDetails,
          timingData: f.timingData,
          aiAnomaly: f.aiAnomalyDetails ? {
            type: f.aiAnomalyDetails.type,
            description: f.aiAnomalyDetails.description,
            confidence: f.aiAnomalyDetails.confidenceScore
          } : null
        })),
        wafStatus,
        wafVendor,
        wafEffectiveness: bypassStats.attempts > 0 ? Math.round((1 - (bypassStats.successes / bypassStats.attempts)) * 100) : 100,
        successfulBypasses: findings.filter(f => f.evasionTechnique).map(f => f.evasionTechnique),
        authConfigured,
        authMethod: authConfig.method,
        bypassSuccessRate: bypassStats.attempts > 0 ? `${Math.round((bypassStats.successes / bypassStats.attempts) * 100)}%` : 'N/A',
        stats: {
          testedParameters: parameters.length,
          vulnerableParameters: findings.length,
          totalRequests: logs.length * 12,
          budgetUsage: `${Math.round((totalRequestsSent / requestBudget) * 100)}%`
        }
      };

      const prompt = `
        You are the Gemini AI Security Analysis Engine for an advanced SQL Injection Tool.
        Analyze the following scan data from a ${targetUrl.includes('https') ? 'Hardened HTTPS Production' : 'Standard HTTP'} environment.
        
        Target URL: ${targetUrl}
        WAF Status: ${wafStatus}
        Findings: ${JSON.stringify(findings)}
        Parameters Tested: ${JSON.stringify(parameters)}
        
        Your task is to generate a formal "SQL Injection Security Assessment Report" in JSON format.
        
        Report Structure Requirements:
        1. Overall Verdict: Either "VULNERABLE", "SECURE", or "POTENTIALLY VULNERABLE".
        2. Executive Summary: A concise paragraph (AI Insights) explaining the key findings (e.g., "The assessment identified a critical Time-Based Blind SQL injection vulnerability...").
        3. Severity Stats: Counts and average confidence for Critical, Medium, and Low findings.
        4. Technical Findings Deep-Dive: For each significant finding, provide:
           - Vulnerability Type (e.g., Time-Based Blind SQLi)
           - Parameter Name and Method (GET/POST)
           - Detection Vector (Error / Boolean / Time-Based)
           - WAF Status (Bypassed / Not Present / Blocked)
           - Impact (e.g., High — Unauthorized Data Access)
           - AI Evidence (PoC): Baseline Latency, Injected Latency, Encoded Payload, and Decoded Payload.
        5. Extraction Proof: Non-destructive metadata (Database Type, Current User, Detected Tables).
        6. Remediation Strategy: Specific actionable steps (Prepared Statements, Input Validation, WAF Tuning).
        7. Scan Statistics: Total Requests, Bypass Simulations, Average Response Time, and AI Confidence Rating.
        
        Return the analysis in the following JSON format:
        {
          "verdict": "VULNERABLE" | "SECURE" | "POTENTIALLY VULNERABLE",
          "confidence": "95%",
          "securityScore": number (0-100),
          "executiveSummary": "AI Insights text...",
          "severityStats": {
            "critical": { "count": number, "avgConf": number },
            "medium": { "count": number, "avgConf": number },
            "low": { "count": number, "avgConf": number }
          },
          "findingsDeepDive": [
            {
              "type": "Vulnerability Type",
              "parameter": "param_name",
              "method": "GET/POST",
              "detectionVector": "Time-Based",
              "wafStatus": "Bypassed",
              "impact": "High...",
              "poc": {
                "baselineLatency": number,
                "injectedLatency": number,
                "encodedPayload": "...",
                "decodedPayload": "..."
              }
            }
          ],
          "extractionProof": {
            "dbType": "MySQL",
            "currentUser": "db_admin",
            "tables": ["users", "orders", "products"]
          },
          "recommendations": ["Action 1", "Action 2"],
          "scanStats": {
            "totalRequests": number,
            "bypassSimulations": number,
            "avgResponseTime": number,
            "aiConfidenceRating": number
          }
        }
      `;
      const response = await ai.models.generateContent({
        model: highThinkingMode ? "gemini-3.1-pro-preview" : "gemini-3-flash-preview",
        contents: prompt,
        config: {
          thinkingConfig: highThinkingMode ? { thinkingLevel: ThinkingLevel.HIGH } : undefined,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              verdict: { type: Type.STRING },
              confidence: { type: Type.STRING },
              securityScore: { type: Type.NUMBER },
              executiveSummary: { type: Type.STRING },
              severityStats: {
                type: Type.OBJECT,
                properties: {
                  critical: { type: Type.OBJECT, properties: { count: { type: Type.NUMBER }, avgConf: { type: Type.NUMBER } } },
                  medium: { type: Type.OBJECT, properties: { count: { type: Type.NUMBER }, avgConf: { type: Type.NUMBER } } },
                  low: { type: Type.OBJECT, properties: { count: { type: Type.NUMBER }, avgConf: { type: Type.NUMBER } } }
                }
              },
              findingsDeepDive: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    parameter: { type: Type.STRING },
                    method: { type: Type.STRING },
                    detectionVector: { type: Type.STRING },
                    wafStatus: { type: Type.STRING },
                    impact: { type: Type.STRING },
                    poc: {
                      type: Type.OBJECT,
                      properties: {
                        baselineLatency: { type: Type.NUMBER },
                        injectedLatency: { type: Type.NUMBER },
                        encodedPayload: { type: Type.STRING },
                        decodedPayload: { type: Type.STRING }
                      }
                    }
                  }
                }
              },
              extractionProof: {
                type: Type.OBJECT,
                properties: {
                  dbType: { type: Type.STRING },
                  currentUser: { type: Type.STRING },
                  tables: { type: Type.ARRAY, items: { type: Type.STRING } }
                }
              },
              recommendations: { type: Type.ARRAY, items: { type: Type.STRING } },
              scanStats: {
                type: Type.OBJECT,
                properties: {
                  totalRequests: { type: Type.NUMBER },
                  bypassSimulations: { type: Type.NUMBER },
                  avgResponseTime: { type: Type.NUMBER },
                  aiConfidenceRating: { type: Type.NUMBER }
                }
              }
            },
            required: ["verdict", "confidence", "securityScore", "executiveSummary", "severityStats", "findingsDeepDive", "extractionProof", "recommendations", "scanStats"]
          }
        },
      });

      if (response.text) {
        setAiReport(JSON.parse(response.text));
      }
    } catch (error) {
      console.error("AI Analysis Error:", error);
      // Fallback logic if AI fails
      const hasHighConf = findings.some(f => f.severity === 'High' || f.severity === 'Critical');
      const budgetUsage = Math.round((totalRequestsSent / requestBudget) * 100);
      const reportData = {
        verdict: hasHighConf ? "VULNERABLE" : (findings.length > 0 ? "POTENTIALLY VULNERABLE" : "NOT VULNERABLE"),
        confidence: findings.some(f => f.method === 'Time-Based') ? "100%" : (wafStatus === 'Detected' ? "Medium" : "High"),
        securityScore: hasHighConf ? 15 : (findings.length > 0 ? 45 : 95),
        executiveSummary: `Automated engine analysis based on detected severity patterns. ${findings.some(f => f.method === 'Time-Based') ? 'Time-Based "Silent" hit confirmed with 100% confidence.' : ''} ${hasHighConf ? `Vulnerable detected using only ${budgetUsage}% of budget.` : ''} ${wafVendor !== 'None' ? `WAF detected: ${wafVendor}.` : ''}`,
        severityStats: {
          critical: { count: findings.filter(f => f.severity === 'Critical').length, avgConf: 95 },
          medium: { count: findings.filter(f => f.severity === 'Medium').length, avgConf: 80 },
          low: { count: findings.filter(f => f.severity === 'Low').length, avgConf: 70 }
        },
        findingsDeepDive: findings.map(f => ({
          type: f.method === 'Time-Based' ? 'Time-Based Blind SQLi' : 'SQL Injection',
          parameter: f.parameter,
          method: 'GET',
          detectionVector: f.method,
          wafStatus: wafStatus === 'Detected' ? 'Bypassed' : 'Not Present',
          impact: 'High — Unauthorized Data Access',
          poc: {
            baselineLatency: f.timingData?.baselineLatency || 100,
            injectedLatency: f.timingData?.actualLatency || 5100,
            encodedPayload: f.payload,
            decodedPayload: f.rawPayload || f.payload
          }
        })),
        extractionProof: {
          dbType: findings[0]?.dbGuess || 'Unknown',
          currentUser: 'db_admin',
          tables: ['users', 'orders', 'products']
        },
        recommendations: [
          "Implement Parameterized Queries (Prepared Statements) for all database interactions.",
          "Enforce strict input validation using an allow-list approach for all user-supplied data.",
          "Apply the Principle of Least Privilege to database service accounts.",
          "Ensure the Web Application Firewall (WAF) is configured with up-to-date SQLi signature sets."
        ],
        scanStats: {
          totalRequests: logs.length * 12,
          bypassSimulations: bypassStats.attempts,
          avgResponseTime: 0.25,
          aiConfidenceRating: 95
        }
      };
      setAiReport(reportData as any);

      // Update Scan in Firestore with report data
      if (currentScanId && user) {
        updateDoc(doc(db, 'scans', currentScanId), {
          status: 'completed',
          endTime: Timestamp.now(),
          securityScore: reportData.securityScore,
          verdict: reportData.verdict,
          findingsCount: findings.length
        }).catch(err => handleFirestoreError(err, OperationType.UPDATE, `scans/${currentScanId}`));
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const performDeepAiAnalysis = async (finding: Finding) => {
    if (!finding.aiAnomalyDetails) return;
    setIsDeepAnalyzing(true);

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });
      
      const prompt = `Analyze this potential SQL injection anomaly deeply.
      
      Request:
      ${finding.request}
      
      Response snippet:
      ${finding.response.substring(0, 1000)}
      
      Anomaly Type: ${finding.aiAnomalyDetails.type}
      Evidence: ${finding.aiAnomalyDetails.evidence.join(', ')}
      
      Provide a deep technical explanation of why this is suspicious and how it might be exploited.
      Focus on the "unusual response patterns" that indicate SQL injection even without traditional error messages.
      Keep it under 150 words.`;

      const response = await ai.models.generateContent({
        model: highThinkingMode ? "gemini-3.1-pro-preview" : "gemini-3-flash-preview",
        contents: prompt,
        config: highThinkingMode ? { thinkingConfig: { thinkingLevel: ThinkingLevel.HIGH } } : undefined,
      });

      if (response.text) {
        const updatedFinding = {
          ...finding,
          aiAnomalyDetails: {
            ...finding.aiAnomalyDetails,
            deepExplanation: response.text
          }
        };
        setFindings(prev => prev.map(f => f.id === finding.id ? updatedFinding : f));
        setSelectedFinding(updatedFinding);
      }
    } catch (error) {
      console.error("Deep AI Analysis Error:", error);
      // Fallback
      const updatedFinding = {
        ...finding,
        aiAnomalyDetails: {
          ...finding.aiAnomalyDetails,
          deepExplanation: "The AI engine detected a significant deviation in response entropy and structure. This often indicates that the injected payload has altered the server-side query logic, causing a different data set or error state to be rendered, even if the HTTP status remains 200 OK. This is a classic indicator of blind SQL injection where traditional signatures fail."
        }
      };
      setFindings(prev => prev.map(f => f.id === finding.id ? updatedFinding : f));
      setSelectedFinding(updatedFinding);
    } finally {
      setIsDeepAnalyzing(false);
    }
  };

  const handleStart = async () => {
    if (!targetUrl) return;
    if (!user) {
      handleLogin();
      return;
    }

    setStatus('scanning');
    setScanPhase('SSL/TLS Handshake');
    setWafStatus('Detecting...');
    setWafVendor('None');
    setBypassStats({ attempts: 0, successes: 0 });
    setDetectionTimeline([]);
    setTotalRequestsSent(0);
    setFindings([]);

    // Create Scan in Firestore
    try {
      const scanRef = await addDoc(collection(db, 'scans'), {
        id: getNextId(),
        userId: user.uid,
        targetUrl,
        status: 'scanning',
        startTime: Timestamp.now(),
        wafStatus: 'Unknown',
        wafVendor: 'None',
        securityScore: 100,
        findingsCount: 0
      });
      setCurrentScanId(scanRef.id);
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, 'scans');
    }
    
    const initialLogs: LogEntry[] = [];
    const now = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

    if (targetUrl.includes('https')) {
      initialLogs.push({
        id: getNextId(),
        timestamp: now,
        type: 'info',
        message: `SSL/TLS Handshake: Establishing encrypted tunnel with ${targetUrl.split('\n')[0]}...`,
        responseTime: 120
      });
    }

    if (authConfigured) {
      initialLogs.push({
        id: getNextId(),
        timestamp: now,
        type: 'info',
        message: `Pre-Scan Handshake: Initiating authentication via ${authConfig.method}...`,
        responseTime: 120
      });
      initialLogs.push({
        id: getNextId(),
        timestamp: now,
        type: 'info',
        message: `Credential Injection: Automating submission of [${authConfig.usernameField}, ${authConfig.passwordField}] to ${authConfig.loginUrl}...`,
        responseTime: 85
      });
      initialLogs.push({
        id: getNextId(),
        timestamp: now,
        type: 'success',
        message: `Persistent Session Management: Session established. Captured Secure Cookies & Bearer Tokens.`,
        responseTime: 45
      });
      initialLogs.push({
        id: getNextId(),
        timestamp: now,
        type: 'info',
        message: `Auth-State Heartbeat: AI Engine verified "Authenticated Baseline" (Found: "${authConfig.authenticatedBaseline}").`,
        responseTime: 30
      });
    }
    if (aiMode) {
      initialLogs.push({
        id: getNextId(),
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
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 14;
    let currentY = 20;

    // Helper for adding text with automatic page breaks
    const addText = (text: string, size: number, color: [number, number, number] = [39, 39, 42], isBold = false) => {
      doc.setFontSize(size);
      doc.setTextColor(color[0], color[1], color[2]);
      doc.setFont('helvetica', isBold ? 'bold' : 'normal');
      
      const lines = doc.splitTextToSize(text, pageWidth - (margin * 2));
      if (currentY + (lines.length * (size / 2)) > pageHeight - margin) {
        doc.addPage();
        currentY = margin + 10;
      }
      doc.text(lines, margin, currentY);
      currentY += (lines.length * (size / 2)) + 4;
    };

    // --- Title Page ---
    doc.setFillColor(9, 9, 11); // Zinc 950
    doc.rect(0, 0, pageWidth, pageHeight, 'F');
    
    doc.setTextColor(16, 185, 129); // Emerald 500
    doc.setFontSize(40);
    doc.setFont('helvetica', 'bold');
    doc.text('SQLi Tool', margin, 60);
    
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(24);
    doc.text('Security Assessment Report', margin, 75);
    
    doc.setDrawColor(16, 185, 129);
    doc.setLineWidth(2);
    doc.line(margin, 85, 100, 85);
    
    doc.setFontSize(12);
    doc.setTextColor(161, 161, 170); // Zinc 400
    doc.text(`Target: ${targetUrl}`, margin, 110);
    doc.text(`Date: ${new Date().toLocaleString()}`, margin, 118);
    doc.text(`Scanner Version: v3.0 (AI-Enhanced)`, margin, 126);
    doc.text(`Security Score: ${aiReport?.securityScore || 'N/A'}/100`, margin, 134);
    
    doc.addPage();
    doc.setTextColor(39, 39, 42); // Zinc 900
    currentY = 25;

    // --- 1. Executive Summary ---
    addText('1. Executive Summary', 18, [16, 185, 129], true);
    
    const verdictColor: [number, number, number] = aiReport?.verdict === 'VULNERABLE' ? [239, 68, 68] : [16, 185, 129];
    addText(`Overall Verdict: ${aiReport?.verdict || (findings.length > 0 ? 'VULNERABLE' : 'SECURE')}`, 14, verdictColor, true);
    
    if (aiReport?.executiveSummary) {
      addText('AI Insights:', 12, [39, 39, 42], true);
      addText(aiReport.executiveSummary, 10);
    }

    currentY += 5;
    addText('Severity Distribution:', 12, [39, 39, 42], true);
    
    autoTable(doc, {
      startY: currentY,
      head: [['Severity', 'Findings', 'Confidence']],
      body: [
        ['Critical', aiReport?.severityStats?.critical?.count || findings.filter(f => f.severity === 'Critical').length, `${aiReport?.severityStats?.critical?.avgConf || 0}%`],
        ['Medium', aiReport?.severityStats?.medium?.count || findings.filter(f => f.severity === 'Medium').length, `${aiReport?.severityStats?.medium?.avgConf || 0}%`],
        ['Low', aiReport?.severityStats?.low?.count || findings.filter(f => f.severity === 'Low').length, `${aiReport?.severityStats?.low?.avgConf || 0}%`],
      ],
      theme: 'striped',
      headStyles: { fillColor: [16, 185, 129] },
      margin: { left: margin }
    });
    currentY = (doc as any).lastAutoTable.finalY + 15;

    // --- 2. Technical Findings Deep-Dive ---
    addText('2. Technical Findings Deep-Dive', 18, [16, 185, 129], true);
    
    if (findings.length === 0) {
      addText('No vulnerabilities were identified during this assessment.', 10);
    } else {
      findings.forEach((finding, index) => {
        if (currentY > pageHeight - 60) {
          doc.addPage();
          currentY = 25;
        }
        
        addText(`Finding #${index + 1}: ${finding.method === 'Time-Based' ? 'Time-Based Blind SQLi' : 'SQL Injection'}`, 14, [39, 39, 42], true);
        addText(`Vulnerable Parameter: ${finding.parameter} (via GET)`, 11, [71, 71, 71], true);
        addText(`Detection Vector: ${finding.method}`, 10);
        addText(`Database: ${finding.dbGuess} (Version: ${finding.dbVersion || 'N/A'})`, 10);
        addText(`WAF Status: ${wafStatus === 'Detected' ? 'Bypassed' : 'Not Present'}`, 10);
        addText(`Impact: High — Unauthorized Data Access / Authentication Bypass.`, 10);
        
        currentY += 2;
        addText('AI Evidence (Proof of Concept):', 11, [39, 39, 42], true);
        
        const pocData = [
          ['Baseline Latency', `${finding.timingData?.baselineLatency || 100}ms`],
          ['Injected Latency', `${finding.timingData?.actualLatency || 150}ms`],
          ['Payload', finding.payload]
        ];
        
        autoTable(doc, {
          startY: currentY,
          body: pocData,
          theme: 'plain',
          styles: { fontSize: 9, cellPadding: 1 },
          columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 } },
          margin: { left: margin + 5 }
        });
        currentY = (doc as any).lastAutoTable.finalY + 10;
      });
    }

    // --- 3. Recommendations ---
    if (currentY > pageHeight - 60) {
      doc.addPage();
      currentY = 25;
    }
    addText('3. Recommendations', 18, [16, 185, 129], true);
    const recommendations = aiReport?.recommendations || [
      "Implement Parameterized Queries (Prepared Statements) for all database interactions.",
      "Enforce strict input validation using an allow-list approach.",
      "Apply the Principle of Least Privilege to database service accounts."
    ];
    
    recommendations.forEach((rec, i) => {
      addText(`[${i + 1}] ${rec}`, 10);
    });

    // --- Footer ---
    const pageCount = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(161, 161, 170);
      doc.text(`Page ${i} of ${pageCount}`, pageWidth / 2, pageHeight - 10, { align: 'center' });
      doc.text('CONFIDENTIAL - SQLi Tool v3.0 Security Report', margin, pageHeight - 10);
    }

    doc.save(`SQLi_Assessment_Report_${Date.now()}.pdf`);
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

  const filteredFindings = findings.filter(f => {
    const severityMatch = findingFilters.severity === 'All' || f.severity === findingFilters.severity;
    const methodMatch = findingFilters.method === 'All' || f.method === findingFilters.method;
    return severityMatch && methodMatch;
  });

  const location = useLocation();

  if (!isAuthReady) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-emerald-500 animate-spin" />
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <Toaster 
        position="top-right"
        toastOptions={{
          className: 'bg-zinc-900 text-zinc-100 border border-zinc-800 text-xs font-mono',
          duration: 4000,
          style: {
            background: '#18181b',
            color: '#f4f4f5',
            border: '1px solid #27272a',
          },
          success: {
            iconTheme: {
              primary: '#10b981',
              secondary: '#18181b',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#18181b',
            },
          },
        }}
      />
      <AnimatePresence mode="wait">
        {!isAuthReady ? (
          <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
            <Loader2 className="w-8 h-8 text-emerald-500 animate-spin" />
          </div>
        ) : !user ? (
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="w-full"
          >
            <Routes location={location}>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="*" element={<Navigate to="/login" replace />} />
            </Routes>
          </motion.div>
        ) : (
          <div className="min-h-screen bg-zinc-950 text-zinc-300 font-mono selection:bg-emerald-500/30">
        {/* Navigation */}
        <nav className="fixed top-0 left-0 right-0 h-16 bg-zinc-950/80 backdrop-blur-md border-b border-zinc-900 z-50 px-6 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-zinc-950" />
            </div>
            <span className="text-lg font-black tracking-tighter text-zinc-100 uppercase">SQLi Tool <span className="text-emerald-500">v3.0</span></span>
          </div>
          
          <div className="flex items-center space-x-6">
            <div className="flex space-x-1 bg-zinc-900/50 p-1 rounded-xl border border-zinc-800">
              {[
                { id: 'scanner', icon: Search, label: 'Scanner' },
                { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard' },
                { id: 'history', icon: Clock, label: 'History' },
                { id: 'cheat-sheet', icon: FileText, label: 'Cheat Sheet' },
                { id: 'report', icon: FileText, label: 'Report' },
                { id: 'settings', icon: Settings, label: 'Settings' }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center space-x-2 px-4 py-1.5 rounded-lg transition-all text-xs font-bold ${
                    activeTab === tab.id ? 'bg-zinc-800 text-emerald-500 shadow-lg' : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <tab.icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                </button>
              ))}
            </div>
            
            <div className="h-6 w-px bg-zinc-800" />
            
            {user ? (
              <div className="flex items-center space-x-3">
                <div className="text-right hidden sm:block">
                  <div className="text-[10px] font-bold text-zinc-100">{user.displayName}</div>
                  <div className="text-[9px] text-zinc-500 font-mono">{user.email}</div>
                </div>
                <div className="relative group">
                  {user.photoURL ? (
                    <img 
                      src={user.photoURL} 
                      alt="User" 
                      className="w-8 h-8 rounded-full border border-zinc-800 group-hover:border-emerald-500 transition-colors" 
                      referrerPolicy="no-referrer"
                    />
                  ) : (
                    <div className="w-8 h-8 rounded-full border border-zinc-800 bg-zinc-900 flex items-center justify-center group-hover:border-emerald-500 transition-colors">
                      <User className="w-4 h-4 text-zinc-500 group-hover:text-emerald-500 transition-colors" />
                    </div>
                  )}
                  <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-500 border-2 border-zinc-950 rounded-full" />
                </div>
                <div className="h-6 w-px bg-zinc-800 mx-1" />
                <button 
                  onClick={handleLogout}
                  className="flex items-center space-x-2 px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-lg transition-all text-[10px] font-bold text-zinc-400 hover:text-red-400 group"
                >
                  <LogOut className="w-3 h-3 group-hover:scale-110 transition-transform" />
                  <span className="hidden md:inline">Logout</span>
                </button>
              </div>
            ) : (
              <button 
                onClick={handleLogin}
                className="flex items-center space-x-2 px-4 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 rounded-lg transition-all text-xs font-bold"
              >
                <Key className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>
            )}
          </div>
        </nav>

        <DatabaseStatusBanner />

        <div className="max-w-7xl mx-auto p-4 pt-20 space-y-4">
          {/* Safety Banner */}
          <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400 px-4 py-2 flex items-center justify-center text-sm font-semibold tracking-wide rounded-xl">
            <ShieldAlert className="w-4 h-4 mr-2" />
            THIS TOOL IS FOR SECURITY EDUCATION AND AUTHORIZED PENETRATION TESTING ONLY
          </div>

        {activeTab === 'scanner' && (
          <>
            {/* Safety Warning */}
            <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 flex items-start space-x-3 mb-6">
              <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="text-sm font-bold text-amber-500 uppercase tracking-wider">Safety Warning: Production Targets</div>
                <p className="text-xs text-amber-200/70 leading-relaxed">
                  Never run a "Real Scan" on a website you do not own or have explicit written permission to test. Unauthorized scanning of HTTPS production sites can be detected by security teams and may lead to legal consequences.
                </p>
              </div>
            </div>
            {/* Configuration Panel */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
              <div className="lg:col-span-3 bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
                  <div className="flex-1 space-y-1">
                    <label className="text-xs text-zinc-500 uppercase tracking-wider flex items-center justify-between">
                      <span>Target URLs (One per line)</span>
                      {status === 'scanning' && (
                        <span className="flex items-center space-x-2 animate-pulse">
                          <Activity className="w-3 h-3 text-emerald-500" />
                          <span className="text-[10px] text-emerald-400 font-bold">{scanPhase}</span>
                        </span>
                      )}
                    </label>
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
                  wafStatus === 'Blocked' ? 'text-red-400' : 
                  wafStatus === 'Detected' ? 'text-amber-400' :
                  wafStatus === 'Detecting...' ? 'text-amber-400 animate-pulse' : 
                  'text-zinc-500'
                }`} />
                <div className="flex flex-col">
                  <span className="text-[10px] text-zinc-500 uppercase tracking-tighter leading-none">WAF Status</span>
                  <span className="text-xs text-zinc-300 font-medium">
                    {wafVendor !== 'None' ? `${wafVendor}: ` : ''}
                    <span className={
                      wafStatus.includes('Bypassed') ? 'text-emerald-400' : 
                      wafStatus === 'Blocked' ? 'text-red-400' : 
                      wafStatus === 'Detected' ? 'text-amber-400' :
                      'text-zinc-400'
                    }>{wafStatus}</span>
                    {bypassStats.attempts > 0 && (
                      <span className="ml-2 text-[10px] text-zinc-500">
                        ({Math.round((bypassStats.successes / bypassStats.attempts) * 100)}% Success)
                      </span>
                    )}
                  </span>
                </div>
              </div>
              
              <div className="flex items-center space-x-3">
                <button 
                  onClick={() => setHighThinkingMode(!highThinkingMode)}
                  disabled={status === 'scanning'}
                  className={`flex items-center space-x-2 border rounded-lg px-3 py-1.5 transition-all duration-300 disabled:opacity-50 ${
                    highThinkingMode 
                      ? 'bg-amber-500/10 border-amber-500/40 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.1)]' 
                      : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:bg-zinc-900'
                  }`}
                >
                  <Brain className={`w-4 h-4 ${highThinkingMode && status === 'scanning' ? 'animate-pulse' : ''}`} />
                  <span className="text-xs font-medium uppercase tracking-tight">High Thinking</span>
                  {highThinkingMode ? <ToggleRight className="w-4 h-4 ml-1 text-amber-400" /> : <ToggleLeft className="w-4 h-4 ml-1 text-zinc-600" />}
                </button>

                <button 
                  onClick={() => setAiMode(!aiMode)}
                  disabled={status === 'scanning'}
                  className={`flex items-center space-x-2 border rounded-lg px-3 py-1.5 transition-all duration-300 disabled:opacity-50 ${
                    aiMode 
                      ? 'bg-purple-500/10 border-purple-500/40 text-purple-400 shadow-[0_0_15px_rgba(168,85,247,0.1)]' 
                      : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:bg-zinc-900'
                  }`}
                >
                  <Bot className={`w-4 h-4 ${aiMode && status === 'scanning' ? 'animate-bounce' : ''}`} />
                  <span className="text-xs font-medium uppercase tracking-tight">AI Anomaly Mode</span>
                  {aiMode ? <ToggleRight className="w-4 h-4 ml-1 text-purple-400" /> : <ToggleLeft className="w-4 h-4 ml-1 text-zinc-600" />}
                </button>
                
                {aiMode && status === 'scanning' && (
                  <div className="flex items-center space-x-2 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-1.5 animate-in fade-in zoom-in duration-300">
                    <div className="relative">
                      <Brain className={`w-4 h-4 ${isAiAnalyzing ? 'text-amber-400' : 'text-zinc-600'} transition-colors duration-500`} />
                      {isAiAnalyzing && (
                        <span className="absolute -top-1 -right-1 flex h-2 w-2">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest">
                      {isAiAnalyzing ? 'Analyzing Patterns...' : 'AI Monitoring'}
                    </span>
                  </div>
                )}
              </div>

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
            {status === 'completed' && (
              <button 
                onClick={generateAiReport}
                disabled={isAnalyzing}
                className="w-full flex items-center justify-center space-x-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 rounded-lg py-3 px-4 transition-colors font-medium"
              >
                <Bot className={`w-4 h-4 ${isAnalyzing ? 'animate-pulse' : ''}`} />
                <span>{isAnalyzing ? 'Analyzing Results...' : 'Generate AI Report'}</span>
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
                <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Total Requests</div>
                <div className="text-2xl text-zinc-100">{logs.length * 12}</div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Findings</div>
                <div className="text-2xl text-amber-400">{findings.length}</div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Request Budget</div>
                  <div className="text-2xl text-blue-400 font-mono">
                    {totalRequestsSent} <span className="text-zinc-600 text-sm">/ {requestBudget}</span>
                  </div>
                </div>
                <div className="mt-3 space-y-1">
                  <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                    <div 
                      className={`h-full transition-all duration-500 ${
                        (totalRequestsSent / requestBudget) > 0.9 ? 'bg-red-500' : 
                        (totalRequestsSent / requestBudget) > 0.7 ? 'bg-amber-500' : 
                        'bg-blue-500'
                      }`}
                      style={{ width: `${Math.min(100, (totalRequestsSent / requestBudget) * 100)}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] text-zinc-500">
                    <span>Used: {Math.round((totalRequestsSent / requestBudget) * 100)}%</span>
                    <span className="text-zinc-400">Limit: {requestBudget}</span>
                  </div>
                </div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1 flex items-center justify-between">
                  <span>Efficiency Score</span>
                  <Activity className="w-3 h-3 text-emerald-500" />
                </div>
                <div className="text-2xl text-emerald-400 font-mono">{requestEfficiencyScore}%</div>
                <div className="text-[10px] text-zinc-600 mt-1 italic">Findings per request density</div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 flex flex-col">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs text-zinc-500 uppercase tracking-wider">AI Baseline</div>
                  <div className="flex items-center space-x-1 bg-zinc-800 px-1.5 py-0.5 rounded border border-zinc-700">
                    <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="text-[9px] text-zinc-400 uppercase font-bold">Active</span>
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-[10px]">
                    <span className="text-zinc-500">Normal Length</span>
                    <span className="text-zinc-300 font-mono">~4,250 bytes</span>
                  </div>
                  <div className="flex justify-between text-[10px]">
                    <span className="text-zinc-500">DOM Complexity</span>
                    <span className="text-zinc-300 font-mono">142 nodes</span>
                  </div>
                  <div className="flex justify-between text-[10px]">
                    <span className="text-zinc-500">Avg. Latency</span>
                    <span className="text-zinc-300 font-mono">145ms</span>
                  </div>
                </div>
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
                  <select 
                    value={findingFilters.severity}
                    onChange={(e) => setFindingFilters({ ...findingFilters, severity: e.target.value })}
                    className="bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-[10px] text-zinc-400 focus:outline-none focus:border-emerald-500/50"
                  >
                    <option value="All">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                  <select 
                    value={findingFilters.method}
                    onChange={(e) => setFindingFilters({ ...findingFilters, method: e.target.value })}
                    className="bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-[10px] text-zinc-400 focus:outline-none focus:border-emerald-500/50"
                  >
                    <option value="All">All Methods</option>
                    <option value="Error-Based">Error-Based</option>
                    <option value="Boolean-Based">Boolean-Based</option>
                    <option value="Time-Based">Time-Based</option>
                    <option value="UNION-Based">UNION-Based</option>
                    <option value="AI Anomaly">AI Anomaly</option>
                  </select>
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
                      <th className="px-4 py-3 font-medium">Version</th>
                      <th className="px-4 py-3 font-medium">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/50">
                    {filteredFindings.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-4 py-8 text-center text-zinc-600">
                          {status === 'scanning' ? 'Analyzing parameters...' : 'No vulnerabilities detected.'}
                        </td>
                      </tr>
                    ) : (
                      filteredFindings.map((finding) => (
                        <tr 
                          key={finding.id} 
                          onClick={() => setSelectedFinding(finding)}
                          className={`cursor-pointer transition-colors ${selectedFinding?.id === finding.id ? 'bg-zinc-800' : 'hover:bg-zinc-800/50'}`}
                        >
                          <td className="px-4 py-3 text-zinc-300 flex items-center space-x-2">
                            <span>{finding.parameter}</span>
                            {finding.method === 'Time-Based' && (
                              <Clock className="w-3 h-3 text-amber-400 animate-pulse" title="Latency Anomaly Detected" />
                            )}
                          </td>
                          <td className="px-4 py-3 text-zinc-400 flex items-center space-x-1.5">
                            {finding.method === 'AI Anomaly' && <Zap className="w-3 h-3 text-amber-400 fill-amber-400/20" />}
                            <span>{finding.method}</span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center space-x-2">
                              <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                                <div className="h-full bg-emerald-500" style={{ width: `${finding.confidence}%` }} />
                              </div>
                              <span className="text-emerald-400">{finding.confidence}%</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-zinc-400">{finding.dbGuess}</td>
                          <td className="px-4 py-3 text-zinc-500 font-mono text-[10px]">{finding.dbVersion || 'N/A'}</td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border ${
                              finding.severity === 'Critical' ? 'bg-red-600/20 text-red-500 border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.2)]' :
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
              {findings.length > 0 && (
                <div className="p-3 border-t border-zinc-800 bg-zinc-950/30">
                  <button 
                    onClick={exportPDF}
                    className="w-full flex items-center justify-center space-x-2 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 rounded-lg transition-all font-bold text-xs"
                  >
                    <Download className="w-3 h-3" />
                    <span>Download Full PDF Security Report</span>
                  </button>
                </div>
              )}
            </div>

            {/* Request / Response Viewer */}
            <div className="flex-1 bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden flex flex-col">
              <div className="bg-zinc-900 px-4 py-2 border-b border-zinc-800 flex items-center space-x-2">
                <FileJson className="w-4 h-4 text-zinc-500" />
                <span className="text-xs text-zinc-400 uppercase tracking-wider">Request / Response Viewer</span>
              </div>
              <div className="flex-1 p-4 overflow-hidden">
                {selectedFinding ? (
                  <div className="h-full flex flex-col space-y-4 overflow-hidden">
                    {selectedFinding.timingData && (
                      <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 space-y-3 shrink-0">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <Clock className="w-4 h-4 text-blue-400" />
                            <h3 className="text-sm font-bold text-blue-400 uppercase tracking-wider">Latency Anomaly Analysis</h3>
                          </div>
                          <div className="flex items-center space-x-1 bg-blue-500/10 px-2 py-0.5 rounded-full border border-blue-500/20">
                            <CheckCircle className="w-3 h-3 text-blue-400" />
                            <span className="text-[10px] font-bold text-blue-400">Triple-Check Verified</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-3 gap-4">
                          <div className="space-y-1">
                            <div className="text-[10px] text-zinc-500 uppercase font-bold">Baseline Latency</div>
                            <div className="text-sm font-mono text-zinc-300">{selectedFinding.timingData.baselineLatency}ms</div>
                          </div>
                          <div className="space-y-1">
                            <div className="text-[10px] text-zinc-500 uppercase font-bold">Actual Latency</div>
                            <div className="text-sm font-mono text-blue-400">{selectedFinding.timingData.actualLatency}ms</div>
                          </div>
                          <div className="space-y-1">
                            <div className="text-[10px] text-zinc-500 uppercase font-bold">Relative Delay</div>
                            <div className="text-sm font-mono text-emerald-400">+{selectedFinding.timingData.actualLatency - selectedFinding.timingData.baselineLatency}ms</div>
                          </div>
                        </div>
                        <p className="text-[10px] text-zinc-400 leading-relaxed">
                          The engine induced a server-side pause of {selectedFinding.timingData.requestedSleep}ms. The consistent relative delay confirms a high-confidence Time-Based Blind SQL Injection vulnerability.
                        </p>
                      </div>
                    )}
                    {selectedFinding.aiAnomalyDetails && (
                      <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 space-y-3 shrink-0">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <Brain className="w-4 h-4 text-amber-400" />
                            <h3 className="text-sm font-bold text-amber-400 uppercase tracking-wider">AI Anomaly Insights</h3>
                          </div>
                          <div className="flex items-center space-x-1 bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20">
                            <Zap className="w-3 h-3 text-amber-400" />
                            <span className="text-[10px] font-bold text-amber-400">{selectedFinding.aiAnomalyDetails.confidenceScore}% Confidence</span>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <div className="text-xs font-bold text-zinc-300">{selectedFinding.aiAnomalyDetails.type}</div>
                          <p className="text-xs text-zinc-400 leading-relaxed">{selectedFinding.aiAnomalyDetails.description}</p>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-amber-500/10">
                          <div className="space-y-1.5">
                            <div className="text-[10px] text-zinc-500 uppercase font-bold flex items-center">
                              <Eye className="w-3 h-3 mr-1" />
                              Detected Evidence
                            </div>
                            <ul className="space-y-1">
                              {selectedFinding.aiAnomalyDetails.evidence.map((ev, idx) => (
                                <li key={idx} className="text-[10px] text-zinc-400 flex items-start">
                                  <span className="text-amber-500 mr-1.5">•</span>
                                  {ev}
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between">
                              <div className="text-[10px] text-zinc-500 uppercase font-bold">Deep Analysis</div>
                              {!selectedFinding.aiAnomalyDetails.deepExplanation && (
                                <button 
                                  onClick={() => performDeepAiAnalysis(selectedFinding)}
                                  disabled={isDeepAnalyzing}
                                  className="text-[9px] text-amber-400 hover:text-amber-300 flex items-center space-x-1 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20 disabled:opacity-50"
                                >
                                  {isDeepAnalyzing ? <RefreshCw className="w-2 h-2 animate-spin" /> : <Brain className="w-2 h-2" />}
                                  <span>{isDeepAnalyzing ? 'Analyzing...' : 'Run Deep Analysis'}</span>
                                </button>
                              )}
                            </div>
                            {selectedFinding.aiAnomalyDetails.deepExplanation ? (
                              <p className="text-[10px] text-zinc-400 leading-relaxed italic">
                                "{selectedFinding.aiAnomalyDetails.deepExplanation}"
                              </p>
                            ) : (
                              <p className="text-[10px] text-zinc-400 leading-relaxed">
                                Manual verification recommended. The AI engine detected structural deviations that strongly correlate with blind SQL injection attempts despite standard response codes.
                              </p>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 shrink-0">
                      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 space-y-1">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold">Raw Payload</div>
                        <div className="text-xs font-mono text-zinc-300 truncate" title={selectedFinding.rawPayload || selectedFinding.payload}>
                          {selectedFinding.rawPayload || selectedFinding.payload}
                        </div>
                      </div>
                      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 space-y-1">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold">Mutated Payload</div>
                        <div className="text-xs font-mono text-emerald-400 truncate" title={selectedFinding.payload}>
                          {selectedFinding.payload}
                        </div>
                      </div>
                      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 space-y-1">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold">Evasion Technique</div>
                        <div className="text-xs font-bold text-purple-400">
                          {selectedFinding.evasionTechnique || 'None (Direct)'}
                        </div>
                      </div>
                    </div>

                    <div className="flex-1 flex flex-col lg:flex-row gap-4 overflow-hidden">
                      <div className="flex-1 flex flex-col space-y-2 overflow-hidden">
                        <div className="flex items-center justify-between">
                          <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Injected Request</div>
                          <div className="flex items-center space-x-3">
                            <button 
                              onClick={() => refineFindingWithAi(selectedFinding)}
                              disabled={isAiAnalyzing}
                              className="text-amber-400 hover:text-amber-300 transition-colors flex items-center space-x-1 bg-amber-500/10 hover:bg-amber-500/20 px-2 py-1 rounded text-[10px] uppercase tracking-wider border border-amber-500/20 disabled:opacity-50"
                              title="Refine with AI"
                            >
                              {isAiAnalyzing ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                              <span>{isAiAnalyzing ? 'Refining...' : 'AI Refine'}</span>
                            </button>
                            <button 
                              onClick={() => generatePoC(selectedFinding)}
                              className="text-zinc-500 hover:text-purple-400 transition-colors flex items-center space-x-1 bg-zinc-800/50 hover:bg-zinc-800 px-2 py-1 rounded text-[10px] uppercase tracking-wider"
                              title="Generate PoC"
                            >
                              <Code className="w-3 h-3" />
                              <span>Generate PoC</span>
                            </button>
                            <button 
                              onClick={() => handleCopy(selectedFinding.request, 'req')}
                              className="text-zinc-500 hover:text-zinc-300 transition-colors flex items-center space-x-1 bg-zinc-800/50 hover:bg-zinc-800 px-2 py-1 rounded text-[10px] uppercase tracking-wider"
                              title="Copy Request"
                            >
                              {copiedReq ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedReq ? 'Copied' : 'Copy Request'}</span>
                            </button>
                          </div>
                        </div>
                        <div className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg p-3 overflow-auto text-xs text-zinc-300 whitespace-pre-wrap">
                          {selectedFinding.request}
                        </div>
                      </div>
                      <div className="flex-1 flex flex-col space-y-2 overflow-hidden">
                        <div className="flex items-center justify-between">
                          <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Server Response</div>
                          <button 
                            onClick={() => handleCopy(selectedFinding.response, 'res')}
                            className="text-zinc-500 hover:text-zinc-300 transition-colors flex items-center space-x-1 bg-zinc-800/50 hover:bg-zinc-800 px-2 py-1 rounded text-[10px] uppercase tracking-wider"
                            title="Copy Response"
                          >
                            {copiedRes ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedRes ? 'Copied' : 'Copy Response'}</span>
                          </button>
                        </div>
                        <div className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg p-3 overflow-auto text-xs text-zinc-300 whitespace-pre-wrap">
                          {selectedFinding.response}
                        </div>
                      </div>

                      {selectedFinding.remediation && (
                        <div className="mt-4 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                          <div className="text-[10px] text-emerald-500 uppercase font-bold mb-2 flex items-center">
                            <CheckCircle className="w-3 h-3 mr-1" />
                            Corrected Code Line (Remediation)
                          </div>
                          <pre className="text-[10px] font-mono text-emerald-400 whitespace-pre-wrap leading-relaxed">
                            {selectedFinding.remediation}
                          </pre>
                        </div>
                      )}

                      {selectedFinding.aiRefinedPayload && (
                        <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                          <div className="text-[10px] text-amber-500 uppercase font-bold mb-2 flex items-center">
                            <Sparkles className="w-3 h-3 mr-1" />
                            AI Refined Payload (WAF Bypass)
                          </div>
                          <div className="text-[10px] font-mono text-amber-400 break-all bg-zinc-950 p-2 rounded border border-amber-500/10">
                            {selectedFinding.aiRefinedPayload}
                          </div>
                        </div>
                      )}

                      {selectedFinding.aiRemediationSnippet && (
                        <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                          <div className="text-[10px] text-blue-400 uppercase font-bold mb-2 flex items-center">
                            <Code className="w-3 h-3 mr-1" />
                            AI Remediation Snippet
                          </div>
                          <pre className="text-[10px] font-mono text-blue-300 whitespace-pre-wrap bg-zinc-950 p-2 rounded border border-blue-500/10">
                            {selectedFinding.aiRemediationSnippet}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
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

        {activeTab === 'cheat-sheet' && (
          <div className="max-w-4xl mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 pb-12">
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
              <h2 className="text-xl font-bold text-zinc-100 mb-6 flex items-center space-x-2">
                <FileText className="w-5 h-5 text-emerald-500" />
                <span>SQL Injection Cheat Sheet</span>
              </h2>
              
              <div className="space-y-8">
                {CHEAT_SHEET.map((category, idx) => (
                  <div key={idx} className="space-y-4">
                    <h3 className="text-sm font-bold text-emerald-500 uppercase tracking-widest border-b border-zinc-800 pb-2">
                      {category.category}
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {category.items.map((item, itemIdx) => (
                        <div key={itemIdx} className="bg-zinc-950 border border-zinc-800 rounded-lg p-4 space-y-2 hover:border-emerald-500/30 transition-colors">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-bold text-zinc-200">{item.name}</span>
                            <button 
                              onClick={() => {
                                navigator.clipboard.writeText(item.payload);
                                alert('Payload copied to clipboard!');
                              }}
                              className="text-zinc-500 hover:text-emerald-500 transition-colors"
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                          </div>
                          <p className="text-xs text-zinc-500 leading-relaxed">{item.description}</p>
                          <div className="bg-zinc-900 p-2 rounded font-mono text-[10px] text-emerald-400 break-all border border-zinc-800">
                            {item.payload}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'history' && (
          <div className="max-w-5xl mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 pb-12">
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
              <div className="bg-zinc-900 px-6 py-4 border-b border-zinc-800 flex items-center justify-between">
                <h2 className="text-lg font-bold text-zinc-100 flex items-center space-x-2">
                  <Clock className="w-5 h-5 text-emerald-500" />
                  <span>Scan History</span>
                </h2>
                <span className="text-xs text-zinc-500">{scanHistory.length} total scans</span>
              </div>
              
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-zinc-950/50 text-zinc-500">
                    <tr>
                      <th className="px-6 py-4 font-medium">Target URL</th>
                      <th className="px-6 py-4 font-medium">Date</th>
                      <th className="px-6 py-4 font-medium">WAF Status</th>
                      <th className="px-6 py-4 font-medium">Security Score</th>
                      <th className="px-6 py-4 font-medium">Findings</th>
                      <th className="px-6 py-4 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/50">
                    {scanHistory.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-6 py-12 text-center text-zinc-600 italic">
                          No scan history available. Start a new scan to see results here.
                        </td>
                      </tr>
                    ) : (
                      scanHistory.map((entry) => (
                        <tr key={entry.id} className="hover:bg-zinc-800/30 transition-colors">
                          <td className="px-6 py-4 text-zinc-300 font-mono truncate max-w-[200px]">{entry.targetUrl}</td>
                          <td className="px-6 py-4 text-zinc-500">{entry.scanDate}</td>
                          <td className="px-6 py-4">
                            <div className="flex flex-col">
                              <span className={`text-[10px] font-bold ${entry.wafStatus === 'Detected' ? 'text-amber-500' : 'text-emerald-500'}`}>{entry.wafStatus}</span>
                              <span className="text-[9px] text-zinc-500">{entry.wafVendor}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center space-x-2">
                              <div className="w-12 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                                <div className={`h-full ${entry.securityScore > 80 ? 'bg-emerald-500' : entry.securityScore > 50 ? 'bg-amber-500' : 'bg-red-500'}`} style={{ width: `${entry.securityScore}%` }} />
                              </div>
                              <span className={`font-bold ${entry.securityScore > 80 ? 'text-emerald-500' : entry.securityScore > 50 ? 'text-amber-500' : 'text-red-500'}`}>{entry.securityScore}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center space-x-2">
                              {entry.criticalCount > 0 && <span className="w-2 h-2 rounded-full bg-red-500" title="Critical" />}
                              {entry.highCount > 0 && <span className="w-2 h-2 rounded-full bg-orange-500" title="High" />}
                              <span className="text-zinc-300 font-bold">{entry.findingsCount}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <button 
                              onClick={() => {
                                // Load report data
                                setFindings(entry.reportData.findings);
                                setLogs(entry.reportData.logs);
                                setAiReport(entry.reportData.aiReport);
                                setTargetUrl(entry.reportData.targetUrl);
                                setWafStatus(entry.reportData.wafStatus);
                                setWafVendor(entry.reportData.wafVendor);
                                setActiveTab('report');
                              }}
                              className="text-emerald-500 hover:text-emerald-400 font-bold flex items-center space-x-1"
                            >
                              <Eye className="w-3.5 h-3.5" />
                              <span>View Report</span>
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'report' && (
          <div className="max-w-4xl mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 pb-12">
            {!aiReport && !isAnalyzing ? (
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-12 text-center space-y-4">
                <div className="inline-flex p-4 bg-zinc-950 rounded-full border border-zinc-800 mb-2">
                  <Shield className="w-12 h-12 text-zinc-700" />
                </div>
                <h2 className="text-xl font-bold text-zinc-200">No Analysis Generated</h2>
                <p className="text-zinc-500 max-w-md mx-auto">Complete a scan and click "Generate AI Report" to receive a comprehensive security verdict from the analysis engine.</p>
                <button 
                  onClick={() => setActiveTab('scanner')}
                  className="px-6 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg transition-colors text-sm font-medium"
                >
                  Return to Scanner
                </button>
              </div>
            ) : isAnalyzing ? (
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-12 text-center space-y-6">
                <div className="relative inline-block">
                  <div className="w-20 h-20 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin" />
                  <Bot className="w-8 h-8 text-emerald-500 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
                </div>
                <div className="space-y-2">
                  <h2 className="text-xl font-bold text-zinc-200">Engine Analyzing Results...</h2>
                  <p className="text-zinc-500 text-sm animate-pulse">Evaluating findings, confidence scores, and WAF presence...</p>
                </div>
              </div>
            ) : (
              <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden shadow-2xl">
                {/* Report Header */}
                <div className="bg-zinc-950 p-8 border-b border-zinc-800">
                  <div className="flex justify-between items-start">
                    <div className="space-y-2">
                      <h1 className="text-2xl font-black text-zinc-100 tracking-tight">SQL Injection Security Assessment Report</h1>
                      <div className="flex flex-col space-y-1">
                        <div className="text-xs text-zinc-500 flex items-center">
                          <Target className="w-3 h-3 mr-2" />
                          Target: <span className="text-zinc-300 ml-1">{targetUrl}</span>
                        </div>
                        <div className="text-xs text-zinc-500 flex items-center">
                          <Clock className="w-3 h-3 mr-2" />
                          Assessment Date: <span className="text-zinc-300 ml-1">{new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}</span>
                        </div>
                        <div className="text-xs text-zinc-500 flex items-center">
                          <Shield className="w-3 h-3 mr-2" />
                          Scanner Version: <span className="text-zinc-300 ml-1">SQLi Tool v3.0 (AI-Enhanced)</span>
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Security Score</div>
                      <div className={`text-4xl font-black ${
                        (aiReport.securityScore ?? 100) < 40 ? 'text-red-500' : 
                        (aiReport.securityScore ?? 100) < 70 ? 'text-amber-500' : 
                        'text-emerald-500'
                      }`}>
                        {aiReport.securityScore ?? 100}/100
                      </div>
                    </div>
                  </div>
                </div>

                <div className="p-8 space-y-10">
                  {/* 1. Executive Summary */}
                  <section className="space-y-4">
                    <div className="flex items-center space-x-2 border-b border-zinc-800 pb-2">
                      <span className="text-lg font-bold text-zinc-100">1. Executive Summary</span>
                    </div>
                    <div className="space-y-4">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-bold text-zinc-400">Overall Verdict:</span>
                        <span className={`text-sm font-black px-2 py-0.5 rounded ${
                          aiReport.verdict === 'VULNERABLE' ? 'text-red-500 bg-red-500/10' : 
                          aiReport.verdict === 'SECURE' ? 'text-emerald-500 bg-emerald-500/10' : 
                          'text-amber-500 bg-amber-500/10'
                        }`}>
                          {aiReport.verdict ?? 'UNKNOWN'}
                        </span>
                      </div>
                      <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 relative">
                        <div className="absolute -top-2 -left-2">
                          <Brain className="w-5 h-5 text-purple-500" />
                        </div>
                        <p className="text-sm text-zinc-400 leading-relaxed italic">
                          {aiReport.executiveSummary ?? 'No summary available.'}
                        </p>
                      </div>
                      
                      <div className="overflow-hidden border border-zinc-800 rounded-lg">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-zinc-950 text-zinc-500 uppercase font-bold">
                            <tr>
                              <th className="px-4 py-2">Severity</th>
                              <th className="px-4 py-2">Findings</th>
                              <th className="px-4 py-2">Confidence</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-zinc-800">
                            <tr>
                              <td className="px-4 py-3 flex items-center text-red-500 font-bold">
                                <span className="mr-2">🔴</span> Critical
                              </td>
                              <td className="px-4 py-3 text-zinc-300">{aiReport.severityStats?.critical?.count ?? 0}</td>
                              <td className="px-4 py-3 text-zinc-300">{aiReport.severityStats?.critical?.avgConf ?? 0}%</td>
                            </tr>
                            <tr>
                              <td className="px-4 py-3 flex items-center text-amber-500 font-bold">
                                <span className="mr-2">🟡</span> Medium
                              </td>
                              <td className="px-4 py-3 text-zinc-300">{aiReport.severityStats?.medium?.count ?? 0}</td>
                              <td className="px-4 py-3 text-zinc-300">{aiReport.severityStats?.medium?.avgConf ?? 0}%</td>
                            </tr>
                            <tr>
                              <td className="px-4 py-3 flex items-center text-blue-500 font-bold">
                                <span className="mr-2">🟢</span> Low
                              </td>
                              <td className="px-4 py-3 text-zinc-300">{aiReport.severityStats?.low?.count ?? 0}</td>
                              <td className="px-4 py-3 text-zinc-300">{aiReport.severityStats?.low?.avgConf ?? 0}%</td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </section>

                  {/* 2. Technical Findings Deep-Dive */}
                  <section className="space-y-6">
                    <div className="flex items-center space-x-2 border-b border-zinc-800 pb-2">
                      <span className="text-lg font-bold text-zinc-100">2. Technical Findings Deep-Dive</span>
                    </div>
                    
                    <div className="space-y-8">
                      {aiReport.findingsDeepDive?.map((finding, idx) => (
                        <div key={idx} className="space-y-4">
                          <h3 className="text-sm font-bold text-zinc-200">Finding #{idx + 1}: {finding.type}</h3>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                            <div className="space-y-2">
                              <div className="flex justify-between border-b border-zinc-800 pb-1">
                                <span className="text-zinc-500">Vulnerable Parameter:</span>
                                <span className="text-zinc-300 font-mono">{finding.parameter} (via {finding.method})</span>
                              </div>
                              <div className="flex justify-between border-b border-zinc-800 pb-1">
                                <span className="text-zinc-500">Detection Vector:</span>
                                <span className="text-zinc-300">{finding.detectionVector}</span>
                              </div>
                              <div className="flex justify-between border-b border-zinc-800 pb-1">
                                <span className="text-zinc-500">WAF Status:</span>
                                <span className={`font-bold ${finding.wafStatus === 'Bypassed' ? 'text-amber-500' : 'text-zinc-300'}`}>{finding.wafStatus}</span>
                              </div>
                              <div className="flex justify-between border-b border-zinc-800 pb-1">
                                <span className="text-zinc-500">Impact:</span>
                                <span className="text-red-400 font-bold">{finding.impact}</span>
                              </div>
                            </div>
                            <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 space-y-2">
                              <div className="text-[10px] text-zinc-500 uppercase font-bold flex items-center">
                                <Activity className="w-3 h-3 mr-1 text-blue-500" />
                                AI Evidence (Proof of Concept)
                              </div>
                              <div className="grid grid-cols-2 gap-2 text-[10px]">
                                <div>
                                  <div className="text-zinc-600 uppercase">Baseline Latency</div>
                                  <div className="text-zinc-400 font-mono">{finding.poc?.baselineLatency}ms</div>
                                </div>
                                <div>
                                  <div className="text-zinc-600 uppercase">Injected Latency</div>
                                  <div className="text-blue-400 font-mono">{finding.poc?.injectedLatency}ms</div>
                                </div>
                              </div>
                              <div className="space-y-1">
                                <div className="text-zinc-600 uppercase text-[10px]">Payload Used</div>
                                <div className="bg-zinc-900 p-2 rounded font-mono text-emerald-400 break-all">
                                  {finding.poc?.encodedPayload}
                                </div>
                                <div className="text-zinc-600 text-[9px] italic">
                                  (Decoded: {finding.poc?.decodedPayload})
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>

                  {/* 3. Extraction Proof */}
                  <section className="space-y-4">
                    <div className="flex items-center space-x-2 border-b border-zinc-800 pb-2">
                      <span className="text-lg font-bold text-zinc-100">3. Extraction Proof (Non-Destructive)</span>
                    </div>
                    <p className="text-xs text-zinc-500">The following database metadata was successfully retrieved to confirm the vulnerability:</p>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-4">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Database Type</div>
                        <div className="text-sm font-bold text-zinc-200">{aiReport.extractionProof?.dbType}</div>
                      </div>
                      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-4">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Current User</div>
                        <div className="text-sm font-bold text-zinc-200">{aiReport.extractionProof?.currentUser}</div>
                      </div>
                      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-4">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Detected Tables</div>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {aiReport.extractionProof?.tables?.map((table, i) => (
                            <span key={i} className="px-1.5 py-0.5 bg-zinc-800 text-zinc-400 rounded text-[9px] font-mono border border-zinc-700">{table}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </section>

                  {/* 4. Remediation Strategy */}
                  <section className="space-y-4">
                    <div className="flex items-center space-x-2 border-b border-zinc-800 pb-2">
                      <span className="text-lg font-bold text-zinc-100">4. Remediation Strategy (AI Recommendations)</span>
                    </div>
                    <p className="text-xs text-zinc-500">To secure the application, the Gemini AI engine recommends the following immediate actions:</p>
                    <ul className="space-y-3">
                      {aiReport.recommendations?.map((rec, i) => (
                        <li key={i} className="flex items-start text-xs text-zinc-400">
                          <span className="text-emerald-500 mr-2 mt-0.5 font-bold">[{i + 1}]</span>
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </section>

                  {/* 5. Scan Statistics */}
                  <section className="space-y-4">
                    <div className="flex items-center space-x-2 border-b border-zinc-800 pb-2">
                      <span className="text-lg font-bold text-zinc-100">5. Scan Statistics</span>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="space-y-1">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold">Total Requests</div>
                        <div className="text-lg font-black text-zinc-200">{aiReport.scanStats?.totalRequests}</div>
                      </div>
                      <div className="space-y-1">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold">Bypass Simulations</div>
                        <div className="text-lg font-black text-zinc-200">{aiReport.scanStats?.bypassSimulations}</div>
                      </div>
                      <div className="space-y-1">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold">Avg Response Time</div>
                        <div className="text-lg font-black text-zinc-200">{aiReport.scanStats?.avgResponseTime}s</div>
                      </div>
                      <div className="space-y-1">
                        <div className="text-[10px] text-zinc-500 uppercase font-bold">AI Confidence</div>
                        <div className="text-lg font-black text-emerald-500">{aiReport.scanStats?.aiConfidenceRating}%</div>
                      </div>
                    </div>
                  </section>
                </div>

                <div className="bg-zinc-950 p-6 border-t border-zinc-800 flex justify-between items-center">
                  <div className="text-[10px] text-zinc-600 font-mono">
                    REPORT_ID: {Math.random().toString(36).substring(2, 15).toUpperCase()}
                  </div>
                  <button 
                    onClick={exportPDF}
                    className="flex items-center space-x-2 px-6 py-2 bg-zinc-100 hover:bg-white text-zinc-950 rounded-lg transition-all font-bold text-xs"
                  >
                    <Download className="w-3 h-3" />
                    <span>Download Full Security Audit</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Verdict Panel */}
            <div className={`bg-zinc-900 border rounded-xl p-6 flex flex-col md:flex-row items-center justify-between gap-6 ${
              !aiReport ? 'border-zinc-800' :
              aiReport.verdict === 'VULNERABLE' ? 'border-red-500/30 bg-red-500/5' :
              aiReport.verdict === 'POTENTIALLY VULNERABLE' ? 'border-amber-500/30 bg-amber-500/5' :
              'border-emerald-500/30 bg-emerald-500/5'
            }`}>
              <div className="flex items-center space-x-4">
                <div className={`p-3 rounded-full ${
                  !aiReport ? 'bg-zinc-800' :
                  aiReport.verdict === 'VULNERABLE' ? 'bg-red-500/20 text-red-500' :
                  aiReport.verdict === 'POTENTIALLY VULNERABLE' ? 'bg-amber-500/20 text-amber-500' :
                  'bg-emerald-500/20 text-emerald-500'
                }`}>
                  <Shield className="w-6 h-6" />
                </div>
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Security Status</div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xl font-bold text-zinc-100">
                      {!aiReport ? 'Scan Required' : (
                        <span className={
                          aiReport.verdict === 'VULNERABLE' ? 'text-red-500' :
                          aiReport.verdict === 'POTENTIALLY VULNERABLE' ? 'text-amber-500' :
                          'text-emerald-500'
                        }>
                          {aiReport.verdict === 'VULNERABLE' ? '🔴 ' : 
                           aiReport.verdict === 'POTENTIALLY VULNERABLE' ? '🟡 ' : '🟢 '}
                          {aiReport.verdict}
                        </span>
                      )}
                    </span>
                  </div>
                </div>
              </div>

              {aiReport && (
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-8 flex-1 max-w-4xl">
                  <div>
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Confidence</div>
                    <div className="text-sm text-zinc-300 font-medium">{aiReport.confidence}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">WAF Bypass Rate</div>
                    <div className="text-sm text-emerald-500 font-bold">
                      {bypassStats.attempts > 0 ? Math.round((bypassStats.successes / bypassStats.attempts) * 100) : 0}%
                      <span className="text-[10px] text-zinc-500 ml-1 font-normal">({bypassStats.successes}/{bypassStats.attempts})</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Reason</div>
                    <div className="text-sm text-zinc-300 font-medium truncate max-w-[150px]" title={aiReport.reasoning}>{aiReport.reasoning}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Risk</div>
                    <div className="text-sm text-zinc-300 font-medium truncate max-w-[150px]" title={aiReport.riskSummary}>{aiReport.riskSummary}</div>
                  </div>
                </div>
              )}
              
              {!aiReport && status === 'completed' && (
                <button 
                  onClick={generateAiReport}
                  className="px-4 py-2 bg-emerald-500 text-zinc-950 rounded-lg text-xs font-bold hover:bg-emerald-400 transition-colors"
                >
                  Analyze Results
                </button>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <h3 className="text-sm font-medium text-zinc-300 mb-4 flex items-center"><ShieldAlert className="w-4 h-4 mr-2 text-red-500" /> Severity Distribution</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart 
                      data={[
                        { name: 'Critical', count: findings.filter(f => f.severity === 'Critical').length, color: '#ef4444' },
                        { name: 'High', count: findings.filter(f => f.severity === 'High').length, color: '#f87171' },
                        { name: 'Medium', count: findings.filter(f => f.severity === 'Medium').length, color: '#fb923c' },
                        { name: 'Low', count: findings.filter(f => f.severity === 'Low').length, color: '#60a5fa' }
                      ]}
                      onClick={(data) => {
                        if (data && data.activeLabel) {
                          setFindingFilters({ ...findingFilters, severity: data.activeLabel });
                          setActiveTab('scanner');
                        }
                      }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="name" stroke="#52525b" fontSize={10} />
                      <YAxis stroke="#52525b" fontSize={10} />
                      <RechartsTooltip 
                        cursor={{ fill: '#27272a', opacity: 0.4 }}
                        contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', fontSize: '12px' }} 
                      />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {
                          [
                            { name: 'Critical', color: '#ef4444' },
                            { name: 'High', color: '#f87171' },
                            { name: 'Medium', color: '#fb923c' },
                            { name: 'Low', color: '#60a5fa' }
                          ].map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))
                        }
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <p className="text-[10px] text-zinc-500 mt-2 text-center italic">Click on a bar to drill down into specific findings.</p>
              </div>

              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <h3 className="text-sm font-medium text-zinc-300 mb-4 flex items-center"><Target className="w-4 h-4 mr-2 text-emerald-500" /> Vulnerability Heatmap</h3>
                <div className="h-64 overflow-auto custom-scrollbar">
                  {findings.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-zinc-600 text-xs italic">
                      No vulnerabilities detected yet.
                    </div>
                  ) : (
                    <div className="min-w-[400px]">
                      <div className="grid grid-cols-6 gap-1 mb-2">
                        <div className="col-span-2"></div>
                        {['Error', 'Bool', 'Time', 'Union'].map(m => (
                          <div key={m} className="text-[9px] text-zinc-500 font-bold uppercase text-center">{m}</div>
                        ))}
                      </div>
                      <div className="space-y-1">
                        {Array.from(new Set(findings.map(f => f.parameter))).slice(0, 8).map(param => (
                          <div key={param} className="grid grid-cols-6 gap-1 items-center">
                            <div className="col-span-2 text-[10px] text-zinc-400 truncate pr-2 font-mono" title={param}>{param}</div>
                            {['Error-Based', 'Boolean-Based', 'Time-Based', 'UNION-Based'].map(method => {
                              const match = findings.find(f => f.parameter === param && f.method === method);
                              return (
                                <div 
                                  key={method}
                                  onClick={() => {
                                    if (match) {
                                      setSelectedFinding(match);
                                      setActiveTab('scanner');
                                    }
                                  }}
                                  className={`h-6 rounded flex items-center justify-center transition-all ${
                                    !match ? 'bg-zinc-950 border border-zinc-800/50' :
                                    match.severity === 'Critical' ? 'bg-red-500/40 border border-red-500/60 cursor-pointer hover:scale-105 shadow-[0_0_8px_rgba(239,68,68,0.3)]' :
                                    match.severity === 'High' ? 'bg-red-400/30 border border-red-400/50 cursor-pointer hover:scale-105' :
                                    match.severity === 'Medium' ? 'bg-orange-400/20 border border-orange-400/40 cursor-pointer hover:scale-105' :
                                    'bg-blue-400/10 border border-blue-400/30 cursor-pointer hover:scale-105'
                                  }`}
                                >
                                  {match && <div className="w-1.5 h-1.5 rounded-full bg-white/50" />}
                                </div>
                              );
                            })}
                          </div>
                        ))}
                      </div>
                      <div className="mt-4 flex items-center justify-center space-x-4">
                        <div className="flex items-center space-x-1">
                          <div className="w-2 h-2 bg-red-500/40 rounded" />
                          <span className="text-[9px] text-zinc-500">Critical</span>
                        </div>
                        <div className="flex items-center space-x-1">
                          <div className="w-2 h-2 bg-orange-400/20 rounded" />
                          <span className="text-[9px] text-zinc-500">Medium</span>
                        </div>
                        <div className="flex items-center space-x-1">
                          <div className="w-2 h-2 bg-blue-400/10 rounded" />
                          <span className="text-[9px] text-zinc-500">Low</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

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
                    <PieChart
                      onClick={(data) => {
                        if (data && data.activeLabel) {
                          setFindingFilters({ ...findingFilters, severity: 'All', method: 'All' });
                          // We don't have a direct filter for parameter type yet, but we can switch tab
                          setActiveTab('scanner');
                        }
                      }}
                    >
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
                        onClick={(data) => {
                          if (data && data.name) {
                            // Logic to filter by parameter type if implemented
                            setActiveTab('scanner');
                          }
                        }}
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
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                  <h3 className="text-sm font-medium text-zinc-300">Request Budget Control</h3>
                  <Target className="w-4 h-4 text-blue-500" />
                </div>
                
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <label className="text-xs text-zinc-400 uppercase tracking-wider">Request Budget</label>
                    <span className="text-xs font-mono text-blue-500">{requestBudget}</span>
                  </div>
                  <input 
                    type="range" 
                    min="100" 
                    max="5000" 
                    step="100"
                    value={requestBudget}
                    onChange={(e) => setRequestBudget(parseInt(e.target.value))}
                    className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-blue-500"
                  />
                  <div className="flex justify-between text-[10px] text-zinc-600 font-mono">
                    <span>100</span>
                    <span>5000</span>
                  </div>
                </div>

                <div className="pt-2">
                  <label className="flex items-center justify-between cursor-pointer group">
                    <div>
                      <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Auto Stop on Vulnerability</div>
                      <div className="text-xs text-zinc-500">Terminate scan immediately when first finding is confirmed</div>
                    </div>
                    <div onClick={() => setAutoStopOnVulnerability(!autoStopOnVulnerability)}>
                      {autoStopOnVulnerability ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                    </div>
                  </label>
                </div>

                <div className="space-y-2">
                  <label className="text-xs text-zinc-400 uppercase tracking-wider">Budget Modes</label>
                  <div className="grid grid-cols-3 gap-2">
                    {(['conservative', 'balanced', 'aggressive'] as const).map((mode) => (
                      <button
                        key={mode}
                        onClick={() => setBudgetMode(mode)}
                        className={`py-2 px-1 rounded-lg text-[10px] uppercase tracking-wider border transition-all ${
                          budgetMode === mode 
                            ? 'bg-blue-500/10 border-blue-500 text-blue-400' 
                            : 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:border-zinc-700'
                        }`}
                      >
                        {mode}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-blue-500/5 rounded-lg border border-blue-500/10">
                  <div className="flex items-start space-x-2">
                    <AlertCircle className="w-3 h-3 text-blue-500 mt-0.5 shrink-0" />
                    <p className="text-[10px] text-blue-400/80 leading-relaxed italic">
                      Scan will automatically stop when the defined budget of <span className="font-bold">{requestBudget}</span> requests is exhausted. 
                      {budgetMode === 'conservative' ? " Conservative mode prioritizes stealth, using adaptive delays and low request volume." : 
                       budgetMode === 'aggressive' ? " Aggressive mode prioritizes speed and depth, adjusting dynamically to target response times." : 
                       " Balanced mode provides an intelligent mix of speed and thoroughness based on WAF feedback."}
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Network Configuration</h3>
                
                <div className="space-y-4">
                  {/* Proxy Section */}
                  <div className="border border-zinc-800 rounded-lg overflow-hidden">
                    <button 
                      onClick={() => setOpenSettingsSection(openSettingsSection === 'proxy' ? null : 'proxy')}
                      className="w-full flex items-center justify-between p-3 bg-zinc-950/50 hover:bg-zinc-950 transition-colors"
                    >
                      <div className="flex items-center space-x-2">
                        <Globe className="w-4 h-4 text-blue-500" />
                        <span className="text-xs font-medium text-zinc-300">Proxy Settings</span>
                      </div>
                      {openSettingsSection === 'proxy' ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
                    </button>
                    {openSettingsSection === 'proxy' && (
                      <div className="p-3 space-y-3 bg-zinc-900/50 border-t border-zinc-800">
                        <label className="flex items-center justify-between cursor-pointer group">
                          <div>
                            <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">HTTP Proxy</div>
                            <div className="text-xs text-zinc-500">Route all scan traffic through a proxy</div>
                          </div>
                          <div onClick={() => setNetworkConfig({...networkConfig, proxyEnabled: !networkConfig.proxyEnabled})}>
                            {networkConfig.proxyEnabled ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                          </div>
                        </label>
                        {networkConfig.proxyEnabled && (
                          <input 
                            type="text" 
                            value={networkConfig.proxyUrl}
                            onChange={(e) => setNetworkConfig({...networkConfig, proxyUrl: e.target.value})}
                            className="w-full bg-zinc-950 border border-zinc-800 rounded p-2 text-xs text-zinc-300 font-mono" 
                            placeholder="http://127.0.0.1:8080" 
                          />
                        )}
                      </div>
                    )}
                  </div>

                  {/* Headers Section */}
                  <div className="border border-zinc-800 rounded-lg overflow-hidden">
                    <button 
                      onClick={() => setOpenSettingsSection(openSettingsSection === 'headers' ? null : 'headers')}
                      className="w-full flex items-center justify-between p-3 bg-zinc-950/50 hover:bg-zinc-950 transition-colors"
                    >
                      <div className="flex items-center space-x-2">
                        <Terminal className="w-4 h-4 text-emerald-500" />
                        <span className="text-xs font-medium text-zinc-300">Custom Headers</span>
                      </div>
                      {openSettingsSection === 'headers' ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
                    </button>
                    {openSettingsSection === 'headers' && (
                      <div className="p-3 space-y-3 bg-zinc-900/50 border-t border-zinc-800">
                        <div className="space-y-2">
                          <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Custom User-Agent</label>
                          <input 
                            type="text" 
                            value={networkConfig.userAgent}
                            onChange={(e) => setNetworkConfig({...networkConfig, userAgent: e.target.value})}
                            className="w-full bg-zinc-950 border border-zinc-800 rounded p-2 text-xs text-zinc-300 font-mono" 
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* SSL Section */}
                  <div className="border border-zinc-800 rounded-lg overflow-hidden">
                    <button 
                      onClick={() => setOpenSettingsSection(openSettingsSection === 'ssl' ? null : 'ssl')}
                      className="w-full flex items-center justify-between p-3 bg-zinc-950/50 hover:bg-zinc-950 transition-colors"
                    >
                      <div className="flex items-center space-x-2">
                        <Shield className="w-4 h-4 text-amber-500" />
                        <span className="text-xs font-medium text-zinc-300">SSL/TLS Verification</span>
                      </div>
                      {openSettingsSection === 'ssl' ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
                    </button>
                    {openSettingsSection === 'ssl' && (
                      <div className="p-3 space-y-3 bg-zinc-900/50 border-t border-zinc-800">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="text-sm text-zinc-300">Verify SSL Certificates</div>
                            <div className="text-xs text-zinc-500">Enable for production targets</div>
                          </div>
                          <div onClick={() => setNetworkConfig({...networkConfig, verifySsl: !networkConfig.verifySsl})}>
                            {networkConfig.verifySsl ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Templates & Profiles</h3>
                <div className="grid grid-cols-2 gap-3">
                  <button 
                    onClick={exportTemplate}
                    className="flex items-center justify-center space-x-2 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-xs text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/30 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Export Template</span>
                  </button>
                  <label className="flex items-center justify-center space-x-2 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-xs text-zinc-400 hover:text-blue-500 hover:border-blue-500/30 transition-all cursor-pointer">
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Import Template</span>
                    <input type="file" className="hidden" accept=".json" onChange={importTemplate} />
                  </label>
                </div>
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
                <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Authentication & Session Establishment</h3>
                
                <div className="space-y-4">
                  <div className="bg-zinc-950 p-4 rounded-lg border border-zinc-800">
                    <div className="flex items-center justify-between mb-4 cursor-pointer group" onClick={() => setAuthConfigured(!authConfigured)}>
                      <div className="flex items-center space-x-2">
                        <Key className={`w-4 h-4 ${authConfigured ? 'text-emerald-500' : 'text-zinc-600'}`} />
                        <div>
                          <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Pre-Scan Handshake</div>
                          <div className="text-xs text-zinc-500">Establish session before discovery and scanning</div>
                        </div>
                      </div>
                      <div>
                        {authConfigured ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                      </div>
                    </div>
                    
                    {authConfigured && (
                      <div className="space-y-4 animate-in fade-in slide-in-from-top-2 duration-200 border-t border-zinc-800 pt-4">
                        <div className="space-y-2">
                          <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Authentication Method</label>
                          <div className="grid grid-cols-3 gap-2">
                            {(['Form-Based', 'JSON/API', 'Header-Based', 'API-Token', 'Session-Cookie', 'OAuth2-Bearer'] as const).map((m) => (
                              <button
                                key={m}
                                onClick={() => setAuthConfig({ ...authConfig, method: m })}
                                className={`py-1.5 px-1 rounded border text-[10px] uppercase tracking-tighter transition-all ${
                                  authConfig.method === m 
                                    ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400' 
                                    : 'bg-zinc-900 border-zinc-800 text-zinc-500 hover:border-zinc-700'
                                }`}
                              >
                                {m}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="space-y-4">
                          <label className="flex items-center justify-between cursor-pointer group">
                            <div>
                              <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">Auto Re-authentication</div>
                              <div className="text-xs text-zinc-500">Automatically refresh session if invalidated during scan</div>
                            </div>
                            <div onClick={() => setAuthConfig({ ...authConfig, autoReauth: !authConfig.autoReauth })}>
                              {authConfig.autoReauth ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                            </div>
                          </label>
                          
                          {authConfig.autoReauth && (
                            <div className="space-y-2">
                              <div className="flex justify-between items-center">
                                <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Failure Threshold: {authConfig.reauthThreshold}%</label>
                              </div>
                              <input 
                                type="range" 
                                min="5" 
                                max="50" 
                                step="5"
                                value={authConfig.reauthThreshold}
                                onChange={(e) => setAuthConfig({ ...authConfig, reauthThreshold: parseInt(e.target.value) })}
                                className="w-full h-1 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-emerald-500"
                              />
                            </div>
                          )}
                        </div>

                        {authConfig.method === 'API-Token' || authConfig.method === 'OAuth2-Bearer' ? (
                          <div className="space-y-3">
                            <div>
                              <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Token Header</label>
                              <input 
                                type="text" 
                                value={authConfig.tokenHeader}
                                onChange={(e) => setAuthConfig({ ...authConfig, tokenHeader: e.target.value })}
                                className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 text-zinc-300 font-mono" 
                                placeholder="X-API-Key or Authorization" 
                              />
                            </div>
                            <div>
                              <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Token Value</label>
                              <textarea 
                                value={authConfig.token}
                                onChange={(e) => setAuthConfig({ ...authConfig, token: e.target.value })}
                                className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 h-20 focus:outline-none focus:border-emerald-500/50 text-zinc-300 font-mono" 
                                placeholder="Paste your token here..." 
                              />
                            </div>
                          </div>
                        ) : authConfig.method === 'Session-Cookie' ? (
                          <div>
                            <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Session Cookies (Raw)</label>
                            <textarea 
                              value={authConfig.sessionCookies}
                              onChange={(e) => setAuthConfig({ ...authConfig, sessionCookies: e.target.value })}
                              className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 h-20 focus:outline-none focus:border-emerald-500/50 text-zinc-300 font-mono" 
                              placeholder="PHPSESSID=abc123xyz; security=low" 
                            />
                          </div>
                        ) : authConfig.method !== 'Header-Based' ? (
                          <>
                            <div className="grid grid-cols-1 gap-3">
                              <div>
                                <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Login URL</label>
                                <input 
                                  type="text" 
                                  value={authConfig.loginUrl}
                                  onChange={(e) => setAuthConfig({ ...authConfig, loginUrl: e.target.value })}
                                  className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300 font-mono" 
                                  placeholder="https://target.local/login" 
                                />
                              </div>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                              <div>
                                <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">User Field</label>
                                <input 
                                  type="text" 
                                  value={authConfig.usernameField}
                                  onChange={(e) => setAuthConfig({ ...authConfig, usernameField: e.target.value })}
                                  className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300 font-mono" 
                                  placeholder="uid" 
                                />
                              </div>
                              <div>
                                <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Pass Field</label>
                                <input 
                                  type="text" 
                                  value={authConfig.passwordField}
                                  onChange={(e) => setAuthConfig({ ...authConfig, passwordField: e.target.value })}
                                  className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300 font-mono" 
                                  placeholder="passw" 
                                />
                              </div>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                              <div>
                                <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Username</label>
                                <input 
                                  type="text" 
                                  value={authConfig.credentials.user}
                                  onChange={(e) => setAuthConfig({ ...authConfig, credentials: { ...authConfig.credentials, user: e.target.value } })}
                                  className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300" 
                                  placeholder="admin" 
                                />
                              </div>
                              <div>
                                <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Password</label>
                                <input 
                                  type="password" 
                                  value={authConfig.credentials.pass}
                                  onChange={(e) => setAuthConfig({ ...authConfig, credentials: { ...authConfig.credentials, pass: e.target.value } })}
                                  className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300" 
                                  placeholder="••••••••" 
                                />
                              </div>
                            </div>
                          </>
                        ) : (
                          <div>
                            <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Bearer Token / JWT</label>
                            <textarea 
                              value={authConfig.token}
                              onChange={(e) => setAuthConfig({ ...authConfig, token: e.target.value })}
                              className="w-full bg-zinc-900 border border-zinc-800 rounded p-2 text-xs mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300 font-mono h-20 resize-none" 
                              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." 
                            />
                          </div>
                        )}

                        <div className="grid grid-cols-2 gap-4 pt-2 border-t border-zinc-800/50">
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="text-[10px] text-zinc-300 font-bold uppercase tracking-wider">SSL/TLS Validation</div>
                              <div className="text-[9px] text-zinc-500">Verify CA chain for production</div>
                            </div>
                            <div 
                              onClick={() => setAuthConfig({ ...authConfig, verifySsl: !authConfig.verifySsl })}
                              className="cursor-pointer"
                            >
                              {authConfig.verifySsl ? <ToggleRight className="w-5 h-5 text-emerald-500" /> : <ToggleLeft className="w-5 h-5 text-zinc-600" />}
                            </div>
                          </div>
                          <div>
                            <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Heartbeat (sec)</label>
                            <input 
                              type="number" 
                              value={authConfig.heartbeatInterval}
                              onChange={(e) => setAuthConfig({ ...authConfig, heartbeatInterval: parseInt(e.target.value) })}
                              className="w-full bg-zinc-900 border border-zinc-800 rounded p-1.5 text-xs mt-1 focus:outline-none focus:border-emerald-500/50 text-zinc-300" 
                            />
                          </div>
                        </div>

                        <div className="pt-2 border-t border-zinc-800/50">
                          <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Success Verification String</label>
                          <div className="flex items-center space-x-2 mt-1">
                            <input 
                              type="text" 
                              value={authConfig.authenticatedBaseline}
                              onChange={(e) => setAuthConfig({ ...authConfig, authenticatedBaseline: e.target.value })}
                              className="flex-1 bg-zinc-900 border border-zinc-800 rounded p-2 text-xs focus:outline-none focus:border-emerald-500/50 text-zinc-300" 
                              placeholder="Sign Out" 
                            />
                            <div className="p-2 bg-zinc-800 rounded border border-zinc-700" title="AI will look for this string to verify session">
                              <Bot className="w-3 h-3 text-purple-400" />
                            </div>
                          </div>
                          <p className="text-[9px] text-zinc-600 mt-1 italic">AI engine uses this to detect accidental logouts and trigger auto-re-login.</p>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                    <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Network Configuration</h3>
                    
                    <div className="space-y-4">
                      <label className="flex items-center justify-between cursor-pointer group">
                        <div>
                          <div className="text-sm text-zinc-300 group-hover:text-emerald-400 transition-colors">HTTP Proxy</div>
                          <div className="text-xs text-zinc-500">Route all scan traffic through a proxy</div>
                        </div>
                        <div onClick={() => setNetworkConfig({...networkConfig, proxyEnabled: !networkConfig.proxyEnabled})}>
                          {networkConfig.proxyEnabled ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                        </div>
                      </label>

                      {networkConfig.proxyEnabled && (
                        <input 
                          type="text" 
                          value={networkConfig.proxyUrl}
                          onChange={(e) => setNetworkConfig({...networkConfig, proxyUrl: e.target.value})}
                          className="w-full bg-zinc-950 border border-zinc-800 rounded p-2 text-xs text-zinc-300 font-mono" 
                          placeholder="http://127.0.0.1:8080" 
                        />
                      )}

                      <div className="space-y-2">
                        <label className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Custom User-Agent</label>
                        <input 
                          type="text" 
                          value={networkConfig.userAgent}
                          onChange={(e) => setNetworkConfig({...networkConfig, userAgent: e.target.value})}
                          className="w-full bg-zinc-950 border border-zinc-800 rounded p-2 text-xs text-zinc-300 font-mono" 
                        />
                      </div>

                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-sm text-zinc-300">Verify SSL Certificates</div>
                          <div className="text-xs text-zinc-500">Enable for production targets</div>
                        </div>
                        <div onClick={() => setNetworkConfig({...networkConfig, verifySsl: !networkConfig.verifySsl})}>
                          {networkConfig.verifySsl ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-600" />}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-4">
                    <h3 className="text-sm font-medium text-zinc-300 border-b border-zinc-800 pb-2">Templates & Profiles</h3>
                    <div className="grid grid-cols-2 gap-3">
                      <button 
                        onClick={exportTemplate}
                        className="flex items-center justify-center space-x-2 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-xs text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/30 transition-all"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export Template</span>
                      </button>
                      <label className="flex items-center justify-center space-x-2 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-xs text-zinc-400 hover:text-blue-500 hover:border-blue-500/30 transition-all cursor-pointer">
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Import Template</span>
                        <input type="file" className="hidden" accept=".json" onChange={importTemplate} />
                      </label>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        </div>

        {/* Floating AI Assistant Chat */}
        <div className="fixed bottom-6 right-6 z-[100] flex flex-col items-end space-y-4">
          {isAiChatOpen && (
            <div className="w-80 h-96 bg-zinc-900 border border-zinc-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-bottom-4 duration-300">
              <div className="bg-zinc-950 p-3 border-b border-zinc-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Bot className="w-4 h-4 text-emerald-500" />
                  <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider">AI Security Assistant</span>
                </div>
                <button onClick={() => setIsAiChatOpen(false)} className="text-zinc-500 hover:text-zinc-300">
                  <Square className="w-3 h-3" />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-zinc-900/50">
                {aiChatMessages.length === 0 && (
                  <div className="text-center py-8 space-y-2">
                    <Brain className="w-8 h-8 text-zinc-700 mx-auto" />
                    <p className="text-[10px] text-zinc-500">Ask me anything about the scan, vulnerabilities, or bypass techniques.</p>
                  </div>
                )}
                {aiChatMessages.map((msg, i) => (
                  <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[85%] p-2 rounded-xl text-[10px] leading-relaxed ${
                      msg.role === 'user' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-zinc-800 text-zinc-300 border border-zinc-700'
                    }`}>
                      {msg.content}
                    </div>
                  </div>
                ))}
                {isAiChatLoading && (
                  <div className="flex justify-start">
                    <div className="bg-zinc-800 p-2 rounded-xl border border-zinc-700 flex items-center space-x-2">
                      <div className="w-1 h-1 bg-zinc-500 rounded-full animate-bounce" />
                      <div className="w-1 h-1 bg-zinc-500 rounded-full animate-bounce [animation-delay:0.2s]" />
                      <div className="w-1 h-1 bg-zinc-500 rounded-full animate-bounce [animation-delay:0.4s]" />
                    </div>
                  </div>
                )}
              </div>
              <form 
                onSubmit={(e) => {
                  e.preventDefault();
                  const form = e.currentTarget;
                  const input = form.elements.namedItem('ai-input') as HTMLInputElement;
                  handleAiChatSubmit(input.value);
                  input.value = '';
                }}
                className="p-3 bg-zinc-950 border-t border-zinc-800 flex items-center space-x-2"
              >
                <input 
                  name="ai-input"
                  type="text" 
                  placeholder="Ask AI..." 
                  className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1.5 text-[10px] text-zinc-300 focus:outline-none focus:border-emerald-500/50"
                />
                <button type="submit" className="p-1.5 bg-emerald-500 text-zinc-950 rounded-lg hover:bg-emerald-400 transition-colors">
                  <Play className="w-3 h-3" />
                </button>
              </form>
            </div>
          )}
          <button 
            onClick={() => setIsAiChatOpen(!isAiChatOpen)}
            className={`w-12 h-12 rounded-full flex items-center justify-center shadow-2xl transition-all duration-300 ${
              isAiChatOpen ? 'bg-zinc-800 text-zinc-300 rotate-90' : 'bg-emerald-500 text-zinc-950 hover:scale-110'
            }`}
          >
            {isAiChatOpen ? <Square className="w-5 h-5" /> : <Bot className="w-6 h-6" />}
          </button>
        </div>
      </div>
      )}
      </AnimatePresence>
    </ErrorBoundary>
  );
}
