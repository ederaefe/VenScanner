/**
 * VenScanner - Frontend Abstraction Layer
 * Encapsulates the file security scan and code analysis engines.
 */

// ==========================================
// 1. UTILITY FUNCTIONS
// ==========================================

/**
 * Reads a File object into an ArrayBuffer
 */
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Reads a File object as Text
 */
function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

/**
 * Calculates the SHA-256 hash of an ArrayBuffer
 */
async function calculateSHA256(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Formats file size bytes into human readable format
 */
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Infers language name based on file extension
 */
function getLanguageFromExtension(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const map = {
    'js': 'JavaScript',
    'jsx': 'JavaScript (React)',
    'ts': 'TypeScript',
    'tsx': 'TypeScript (React)',
    'py': 'Python',
    'c': 'C',
    'cpp': 'C++',
    'h': 'C/C++ Header',
    'java': 'Java',
    'go': 'Go',
    'html': 'HTML',
    'css': 'CSS',
    'php': 'PHP',
    'sh': 'Bash Shell',
    'rb': 'Ruby',
    'pl': 'Perl',
    'sql': 'SQL',
    'rs': 'Rust',
    'swift': 'Swift',
    'kt': 'Kotlin'
  };
  return map[ext] || null;
}

// ==========================================
// 2. FILE SCANNING ENGINE (Abstracted)
// ==========================================

class FileScannerEngine {
  /**
   * Scans a file locally and checks hash reputation remotely
   */
  static async scan(file, callbacks = {}) {
    const { onProgress = () => {}, onComplete = () => {}, onError = () => {} } = callbacks;

    try {
      onProgress('Calculating SHA-256 checksum...');
      const buffer = await readFileAsArrayBuffer(file);
      const hash = await calculateSHA256(buffer);
      
      onProgress(`SHA-256 computed: ${hash.substring(0, 16)}...`);

      // 1. Perform EICAR check (Standard Antivirus Test File)
      onProgress('Scanning for malware signatures...');
      const textContent = new TextDecoder('utf-8').decode(new Uint8Array(buffer));
      // Clean string match for EICAR
      const eicarPattern = /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/;
      if (eicarPattern.test(textContent.trim())) {
        onComplete({
          verdict: 'MALICIOUS',
          hash,
          fileName: file.name,
          fileSize: formatBytes(file.size),
          fileType: file.type || 'Unknown Type',
          reputationScore: -100,
          issues: [{
            title: 'Malware Signature Detected',
            description: 'The file contains the EICAR Standard Anti-Virus Test File signature. This file is flagged as malicious.',
            severity: 'CRITICAL'
          }],
          vtStats: { malicious: 1, suspicious: 0, harmless: 0, undetected: 0 }
        });
        return;
      }

      // 2. Perform Magic Byte verification to check for spoofed file extensions
      onProgress('Analyzing magic byte headers...');
      const headerBytes = new Uint8Array(buffer.slice(0, 8));
      const headerHex = Array.from(headerBytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      
      const ext = file.name.split('.').pop().toLowerCase();
      let detectedType = 'Unknown';
      let isSpoofed = false;
      let spoofMessage = '';

      // Define standard magic bytes
      if (headerHex.startsWith('89 50 4E 47 0D 0A 1A 0A')) {
        detectedType = 'png';
      } else if (headerHex.startsWith('FF D8 FF')) {
        detectedType = 'jpg';
      } else if (headerHex.startsWith('25 50 44 46')) { // %PDF
        detectedType = 'pdf';
      } else if (headerHex.startsWith('50 4B 03 04')) { // PK zip
        detectedType = 'zip'; // Could also be docx, xlsx, pptx
      } else if (headerHex.startsWith('4D 5A')) { // MZ exe
        detectedType = 'exe';
      } else if (headerHex.startsWith('7F 45 4C 46')) {
        detectedType = 'elf';
      } else if (headerHex.startsWith('47 49 46 38')) {
        detectedType = 'gif';
      }

      // Verify extension against detected type
      const imageExtensions = ['png', 'jpg', 'jpeg', 'gif'];
      const archiveExtensions = ['zip', 'docx', 'xlsx', 'pptx', 'jar'];
      
      if (detectedType === 'exe' && ext !== 'exe' && ext !== 'dll') {
        isSpoofed = true;
        spoofMessage = `Spoofing Detected: The file extension is ".${ext}" but the header indicates a binary Windows executable (MZ).`;
      } else if (detectedType === 'pdf' && ext !== 'pdf') {
        isSpoofed = true;
        spoofMessage = `Spoofing Detected: The file extension is ".${ext}" but the header indicates a PDF document.`;
      } else if (detectedType === 'png' && !imageExtensions.includes(ext)) {
        isSpoofed = true;
        spoofMessage = `Spoofing Detected: The file extension is ".${ext}" but the header indicates a PNG image.`;
      } else if (detectedType === 'jpg' && !imageExtensions.includes(ext)) {
        isSpoofed = true;
        spoofMessage = `Spoofing Detected: The file extension is ".${ext}" but the header indicates a JPEG image.`;
      } else if (detectedType === 'zip' && !archiveExtensions.includes(ext) && ext !== 'zip') {
        isSpoofed = true;
        spoofMessage = `Spoofing Detected: The file extension is ".${ext}" but the header indicates a compressed archive or office container (ZIP/PK).`;
      }

      const issues = [];
      if (isSpoofed) {
        issues.push({
          title: 'File Extension Spoofing',
          description: spoofMessage,
          severity: 'HIGH'
        });
      }

      // 3. Perform VirusTotal Check via Serverless API
      onProgress('Consulting remote threat intelligence database...');
      try {
        const res = await fetch('/api/scan-hash', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hash })
        });

        if (!res.ok) {
          throw new Error(`API returned status ${res.status}`);
        }

        const data = await res.json();
        
        let verdict = 'SAFE';
        let reputationScore = 0;
        let vtStats = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };

        if (data.status === 'known') {
          vtStats = data.stats;
          reputationScore = data.reputation;
          
          if (vtStats.malicious > 0) {
            verdict = 'MALICIOUS';
            issues.push({
              title: `${vtStats.malicious} Antivirus Engines flagged this hash`,
              description: `This file hash has been reported as malicious by ${vtStats.malicious} engine(s) on VirusTotal.`,
              severity: vtStats.malicious > 3 ? 'CRITICAL' : 'HIGH'
            });
          } else if (vtStats.suspicious > 0 || reputationScore < 0) {
            verdict = 'SUSPICIOUS';
            issues.push({
              title: 'Suspicious reputation detected',
              description: `This file hash is flagged as suspicious by security scanners or holds a negative reputation score of ${reputationScore}.`,
              severity: 'MEDIUM'
            });
          }
        } else if (data.status === 'unconfigured') {
          issues.push({
            title: 'Cloud Scanner Key Missing',
            description: 'Vercel environment variables do not include a VirusTotal API Key. Remote checks were bypassed; file validated locally only.',
            severity: 'LOW'
          });
        }

        // If spoofing occurred but VT says 0 malicious, verdict is still SUSPICIOUS
        if (isSpoofed && verdict === 'SAFE') {
          verdict = 'SUSPICIOUS';
        }

        onComplete({
          verdict,
          hash,
          fileName: file.name,
          fileSize: formatBytes(file.size),
          fileType: file.type || (detectedType !== 'Unknown' ? `${detectedType.toUpperCase()} file` : `.${ext} file`),
          reputationScore,
          issues,
          vtStats
        });

      } catch (apiErr) {
        // Fallback if the API fails
        issues.push({
          title: 'Remote Scan Bypassed',
          description: `Unable to verify reputation online: ${apiErr.message}. Local heuristics report no immediate threats.`,
          severity: 'LOW'
        });

        onComplete({
          verdict: isSpoofed ? 'SUSPICIOUS' : 'SAFE',
          hash,
          fileName: file.name,
          fileSize: formatBytes(file.size),
          fileType: file.type || `.${ext} file`,
          reputationScore: 0,
          issues,
          vtStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 }
        });
      }

    } catch (err) {
      onError(err);
    }
  }
}

// ==========================================
// 3. AI CODE AUDITING ENGINE (Abstracted)
// ==========================================

class CodeAnalyzerEngine {
  /**
   * Audits code files for security vulnerabilities and bugs
   */
  static async analyze(file, callbacks = {}) {
    const { onProgress = () => {}, onComplete = () => {}, onError = () => {} } = callbacks;

    try {
      const language = getLanguageFromExtension(file.name);
      if (!language) {
        throw new Error('Unsupported extension for code scanning');
      }

      onProgress('Reading code file contents...');
      const code = await readFileAsText(file);
      
      if (!code.trim()) {
        onComplete([]);
        return;
      }

      // Tier 1: Try Chrome Local AI (window.ai)
      onProgress('Attempting local browser-based AI analysis (Gemini Nano)...');
      try {
        const localAIReport = await this.scanWithLocalAI(code, file.name);
        if (localAIReport && Array.isArray(localAIReport)) {
          onComplete(localAIReport, 'Local AI (Chrome Gemini Nano)');
          return;
        }
      } catch (localAIErr) {
        onProgress(`Local AI bypassed: ${localAIErr.message}. Trying cloud API...`);
      }

      // Tier 2: Try Vercel Serverless Gemini API
      onProgress('Routing code audit request to serverless cloud AI...');
      try {
        const cloudAIReport = await this.scanWithCloudAI(code, language);
        if (cloudAIReport && Array.isArray(cloudAIReport)) {
          onComplete(cloudAIReport, 'Vercel Cloud AI (Gemini API)');
          return;
        }
      } catch (cloudAIErr) {
        onProgress(`Cloud AI bypassed: ${cloudAIErr.message}. Executing local heuristics...`);
      }

      // Tier 3: Static Heuristics Engine
      onProgress('Running static heuristic vulnerability matcher...');
      const heuristicReport = this.scanWithHeuristics(code, file.name);
      // Introduce a slight procedural delay for UX satisfying feedback
      await new Promise(r => setTimeout(r, 600));
      onComplete(heuristicReport, 'Static Heuristic Parser');

    } catch (err) {
      onError(err);
    }
  }

  /**
   * Tier 1: Chrome window.ai implementation
   */
  static async scanWithLocalAI(code, filename) {
    // Check Prompt API availability
    if (typeof window === 'undefined' || !window.ai || (!window.ai.assistant && !window.ai.createTextSession)) {
      throw new Error('window.ai Prompt API not supported by browser');
    }

    onProgress('Local AI detected. Spawning neural runtime session...');
    
    // Support newer standard window.ai.assistant or older window.ai
    let session;
    if (window.ai.assistant) {
      session = await window.ai.assistant.create({
        systemPrompt: "You are a code vulnerability auditor. Analyze the code. Return ONLY a valid JSON array of objects. Each object must contain keys: 'severity' (CRITICAL, HIGH, MEDIUM, LOW), 'line' (integer line number), 'title' (short description), 'description' (full context), and 'remediation' (code fix)."
      });
    } else {
      session = await window.ai.createTextSession();
    }

    const systemPrompt = "Analyze this code for vulnerabilities, secrets, bugs, or injections. You MUST output ONLY a valid JSON array of objects. Do not wrap in markdown code blocks. Each object contains: 'severity' (CRITICAL, HIGH, MEDIUM, LOW), 'line' (integer), 'title' (string), 'description' (string), 'remediation' (string).";
    
    const prompt = `${systemPrompt}\n\nCode file [${filename}]:\n${code}`;
    const result = await session.prompt(prompt);
    
    // Clean potential markdown blocks
    let cleaned = result.trim();
    if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```(json)?/, '').replace(/```$/, '');
    }
    
    return JSON.parse(cleaned.trim());
  }

  /**
   * Tier 2: Cloud API call to Vercel Endpoint
   */
  static async scanWithCloudAI(code, language) {
    const res = await fetch('/api/analyze-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, language })
    });

    if (!res.ok) {
      throw new Error(`Cloud API returned status ${res.status}`);
    }

    const data = await res.json();
    if (data.status === 'success' && Array.isArray(data.report)) {
      return data.report;
    }
    
    if (data.status === 'unconfigured') {
      throw new Error('Gemini API key is unconfigured on backend');
    }
    
    throw new Error(data.error || 'Unknown server response layout');
  }

  /**
   * Tier 3: Client-side Static analysis regex rules
   */
  static scanWithHeuristics(code, filename) {
    const lines = code.split('\n');
    const report = [];

    // Helper to add issues
    const addIssue = (lineNum, severity, title, desc, remediate) => {
      report.push({
        severity,
        line: lineNum,
        title,
        description: desc,
        remediation: remediate
      });
    };

    // Regex scanners
    const patterns = [
      {
        regex: /eval\s*\(/,
        severity: 'CRITICAL',
        title: 'Unsafe Dynamic Execution (eval)',
        desc: 'Use of eval() executes strings as code, exposing the application to injection vulnerabilities.',
        remediator: 'Avoid eval(). Parse strings as structured data (e.g. JSON.parse()) or use static methods.'
      },
      {
        regex: /(strcpy|strcat|gets)\s*\(/,
        severity: 'HIGH',
        title: 'Memory Safety Vulnerability (Buffer Overflow)',
        desc: 'Unbounded buffer operations in C/C++ can overwrite stack memory and allow remote code execution.',
        remediator: 'Replace with safer alternatives: strncpy(), strncat(), or fgets().'
      },
      {
        regex: /(SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*\w+/i,
        severity: 'HIGH',
        title: 'Potential SQL Injection',
        desc: 'Direct string concatenation in database queries is vulnerable to SQL command injections.',
        remediator: 'Use parameterized queries or prepared statements.'
      },
      {
        regex: /(\.innerHTML\s*=.*(\+|=).*)/,
        severity: 'MEDIUM',
        title: 'DOM-based Cross-Site Scripting (XSS)',
        desc: 'Writing raw parameters directly into innerHTML can execute arbitrary script payloads in the user browser.',
        remediator: 'Use element.textContent or element.setAttribute() instead, or sanitize user input before rendering.'
      },
      {
        regex: /(api[_-]?key|secret|password|passwd|private[_-]?key)\s*[:=]\s*['"`][A-Za-z0-9\/+_-]{12,}['"`]/i,
        severity: 'HIGH',
        title: 'Hardcoded Secret/Credentials Detected',
        desc: 'Sensitive API keys, passwords, or credentials stored directly in source code are easily compromised.',
        remediator: 'Extract secrets to secure environment variables (.env files) or use credential vaults.'
      },
      {
        regex: /(createHash\s*\(\s*['"]md5['"]\s*\)|createHash\s*\(\s*['"]sha1['"]\s*\))/i,
        severity: 'MEDIUM',
        title: 'Weak Cryptographic Algorithm',
        desc: 'MD5 and SHA-1 algorithms contain cryptographic collisions and are insecure for hashing passwords or signatures.',
        remediator: 'Upgrade to modern algorithms like SHA-256 or bcrypt.'
      },
      {
        regex: /rejectUnauthorized\s*:\s*false/i,
        severity: 'HIGH',
        title: 'TLS Certificate Verification Disabled',
        desc: 'Disabling certificate validation bypasses SSL/TLS security, allowing Man-in-the-Middle (MitM) attacks.',
        remediator: 'Enable certificate validation (set rejectUnauthorized to true) and use valid certificates.'
      }
    ];

    // Scan line by line
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const lineNum = i + 1;

      for (const rule of patterns) {
        if (rule.regex.test(lineText)) {
          addIssue(lineNum, rule.severity, rule.title, rule.desc, rule.remediator);
        }
      }
    }

    return report;
  }
}
