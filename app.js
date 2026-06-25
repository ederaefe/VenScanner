/**
 * VenScanner - Frontend Abstraction Layer
 * Encapsulates the file security scan and code analysis engines.
 * Optimized for memory safety, modern window.ai interfaces, and PWA animated favicons.
 */

// ==========================================
// 1. UTILITY & DIAGNOSTIC FUNCTIONS
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
 * Robust extraction of the file extension
 */
function getFileExtension(filename) {
  if (!filename || typeof filename !== 'string') return '';
  const trimmed = filename.trim();
  
  // Extract the last path component (basename) to prevent directory manipulation errors
  const parts = trimmed.split('/');
  const basename = parts[parts.length - 1];
  
  // Handle dotfiles without extensions (e.g. .gitignore)
  if (basename.startsWith('.') && !basename.slice(1).includes('.')) {
    return '';
  }
  
  const extParts = basename.split('.');
  if (extParts.length < 2) {
    return '';
  }
  
  return extParts[extParts.length - 1].toLowerCase();
}

/**
 * Infers language name based on file extension
 */
function getLanguageFromExtension(filename) {
  const ext = getFileExtension(filename);
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
// 2. ANIMATED FAVICON ENGINE
// ==========================================

class FaviconAnimator {
  constructor() {
    this.canvas = document.createElement('canvas');
    this.canvas.width = 32;
    this.canvas.height = 32;
    this.ctx = this.canvas.getContext('2d');
    this.frames = 4;
    this.currentFrame = 0;
    this.intervalId = null;
    
    // Find or create dynamic link element
    this.link = document.getElementById('dynamic-favicon');
    if (!this.link) {
      this.link = document.createElement('link');
      this.link.id = 'dynamic-favicon';
      this.link.rel = 'icon';
      this.link.type = 'image/png';
      document.head.appendChild(this.link);
    }
  }

  drawFrame(frame) {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, 32, 32);

    // Draw background outer circle (radar scope) in deep slate
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(16, 16, 13, 0, Math.PI * 2);
    ctx.stroke();

    // Draw scanning sweep line based on frame (0, 90, 180, 270 degrees)
    const angle = (frame * Math.PI) / 2; // in radians
    ctx.strokeStyle = '#0ea5e9'; // Cyan sweep color
    ctx.lineWidth = 3;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.moveTo(16, 16);
    ctx.lineTo(
      16 + Math.cos(angle) * 12,
      16 + Math.sin(angle) * 12
    );
    ctx.stroke();

    // Draw core active dot
    ctx.fillStyle = '#10b981'; // Green active dot
    ctx.beginPath();
    ctx.arc(16, 16, 3, 0, Math.PI * 2);
    ctx.fill();

    // Update link href
    this.link.href = this.canvas.toDataURL('image/png');
  }

  start() {
    if (this.intervalId) return;
    this.drawFrame(this.currentFrame);
    this.intervalId = setInterval(() => {
      this.currentFrame = (this.currentFrame + 1) % this.frames;
      this.drawFrame(this.currentFrame);
    }, 400); // 400ms frame transition
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }
}

// ==========================================
// 3. FILE SCANNING ENGINE (Abstracted)
// ==========================================

class FileScannerEngine {
  /**
   * Scans a file locally and checks hash reputation remotely
   */
  static async scan(file, callbacks = {}) {
    const { onProgress = () => {}, onComplete = () => {}, onError = () => {} } = callbacks;

    try {
      // Yield to the rendering queue if the file size is large
      if (file.size > 10 * 1024 * 1024) { // 10MB
        onProgress('Warning: Large file detected. Hashing may lock the browser thread temporarily...');
        await new Promise(r => requestAnimationFrame(r));
      }

      onProgress('Calculating SHA-256 checksum...');
      const buffer = await readFileAsArrayBuffer(file);
      const hash = await calculateSHA256(buffer);
      
      onProgress(`SHA-256 computed: ${hash.substring(0, 16)}...`);

      // 1. Perform Memory-Safe EICAR check
      onProgress('Scanning for malware signatures...');
      
      // Slice only the first 2048 bytes to mitigate memory allocation spikes
      const sliceSize = Math.min(buffer.byteLength, 2048);
      const sliceBuffer = buffer.slice(0, sliceSize);
      const textContent = new TextDecoder('utf-8').decode(new Uint8Array(sliceBuffer));
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
      
      const ext = getFileExtension(file.name);
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
        detectedType = 'zip';
      } else if (headerHex.startsWith('4D 5A')) { // MZ Windows executable
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
// 4. AI CODE AUDITING ENGINE (Abstracted)
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
        const localAIReport = await this.scanWithLocalAI(code, file.name, onProgress);
        if (localAIReport && Array.isArray(localAIReport)) {
          onComplete(localAIReport, 'Local AI (Chrome Gemini Nano)');
          return;
        }
      } catch (localAIError) {
        onProgress(`Local AI bypassed: ${localAIError.message}. Trying cloud API...`);
      }

      // Tier 2: Try Vercel Serverless Gemini API
      onProgress('Routing code audit request to serverless cloud AI...');
      try {
        const cloudAIReport = await this.scanWithCloudAI(code, language);
        if (cloudAIReport && Array.isArray(cloudAIReport)) {
          onComplete(cloudAIReport, 'Vercel Cloud AI (Gemini API)');
          return;
        }
      } catch (cloudAIError) {
        onProgress(`Cloud AI bypassed: ${cloudAIError.message}. Executing local heuristics...`);
      }

      // Tier 3: Static Heuristics Engine
      onProgress('Running static heuristic vulnerability matcher...');
      const heuristicReport = this.scanWithHeuristics(code, file.name);
      await new Promise(r => setTimeout(r, 600));
      onComplete(heuristicReport, 'Static Heuristic Parser');

    } catch (err) {
      onError(err);
    }
  }

  /**
   * Tier 1: Chrome window.ai implementation (Up-to-date with window.ai.languageModel specs)
   */
  static async scanWithLocalAI(code, filename, onProgress) {
    if (typeof window === 'undefined' || !window.ai) {
      throw new Error('window.ai not supported by browser');
    }

    onProgress('Local AI detected. Checking capability APIs...');
    
    let session;
    const systemPrompt = "Analyze this code for vulnerabilities, secrets, bugs, or injections. You MUST output ONLY a valid JSON array of objects. Do not wrap in markdown code blocks. Each object contains: 'severity' (CRITICAL, HIGH, MEDIUM, LOW), 'line' (integer), 'title' (string), 'description' (string), 'remediation' (string).";

    // 1. Try standard window.ai.languageModel (Chrome 128+)
    if (window.ai.languageModel) {
      const capabilities = await window.ai.languageModel.capabilities();
      if (capabilities.available === 'no') {
        throw new Error('Chrome local model has not been initialized or downloaded.');
      }
      session = await window.ai.languageModel.create({
        systemPrompt: systemPrompt
      });
    } 
    // 2. Try window.ai.assistant (Legacy intermediate standard)
    else if (window.ai.assistant) {
      session = await window.ai.assistant.create({
        systemPrompt: systemPrompt
      });
    } 
    // 3. Fallback to older text session
    else if (window.ai.createTextSession) {
      session = await window.ai.createTextSession();
    } else {
      throw new Error('No compatible browser on-device Prompt API endpoints found.');
    }

    const prompt = `${systemPrompt}\n\nCode file [${filename}]:\n${code}`;
    const result = await session.prompt(prompt);
    
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
    
    throw new Error(data.error || 'Unknown server response');
  }

  /**
   * Tier 3: Client-side Static analysis regex rules
   */
  static scanWithHeuristics(code, filename) {
    const lines = code.split('\n');
    const report = [];

    const addIssue = (lineNum, severity, title, desc, remediate) => {
      report.push({
        severity,
        line: lineNum,
        title,
        description: desc,
        remediation: remediate
      });
    };

    const patterns = [
      {
        regex: /eval\s*\(/,
        severity: 'CRITICAL',
        title: 'Unsafe Dynamic Execution (eval)',
        desc: 'Use of eval() executes strings as code, exposing the application to injection vulnerabilities.',
        remediator: 'Avoid eval(). Parse strings as structured data (e.g. JSON.parse()) or use static parameters.'
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
