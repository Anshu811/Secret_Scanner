const fs   = require('fs');
const path = require('path');

// ══════════════════════════════════════════════════════════════
//  SECRET PATTERNS  (30 types)
// ══════════════════════════════════════════════════════════════
const PATTERNS = [
  { name: 'AWS Access Key',      severity: 'critical', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key',      severity: 'critical', regex: /aws_secret_access_key\s*=\s*[A-Za-z0-9\/+=]{40}/gi },
  { name: 'GitHub Token',        severity: 'critical', regex: /ghp_[A-Za-z0-9]{36}/g },
  { name: 'GitHub PAT',          severity: 'critical', regex: /github_pat_[A-Za-z0-9_]{82}/g },
  { name: 'OpenAI API Key',      severity: 'critical', regex: /sk-[A-Za-z0-9]{48}/g },
  { name: 'Anthropic API Key',   severity: 'critical', regex: /sk-ant-[A-Za-z0-9\-_]{40,}/g },
  { name: 'Stripe Secret Key',   severity: 'critical', regex: /sk_live_[0-9a-zA-Z]{24}/g },
  { name: 'MongoDB URI',         severity: 'critical', regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s"'`]+/gi },
  { name: 'PostgreSQL URI',      severity: 'critical', regex: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s"'`]+/gi },
  { name: 'MySQL URI',           severity: 'critical', regex: /mysql:\/\/[^:]+:[^@]+@[^\s"'`]+/gi },
  { name: 'Private Key',         severity: 'critical', regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'DigitalOcean Token',  severity: 'critical', regex: /dop_v1_[a-f0-9]{64}/g },
  { name: 'Shopify Token',       severity: 'critical', regex: /shpat_[A-Za-z0-9]{32}/g },
  { name: 'Google API Key',      severity: 'high',     regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Slack Token',         severity: 'high',     regex: /xox[baprs]-[0-9A-Za-z\-]{10,48}/g },
  { name: 'Slack Webhook',       severity: 'high',     regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/g },
  { name: 'SendGrid Key',        severity: 'high',     regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g },
  { name: 'Twilio SID',          severity: 'high',     regex: /AC[a-zA-Z0-9]{32}/g },
  { name: 'JWT Token',           severity: 'high',     regex: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g },
  { name: 'Firebase Config',     severity: 'high',     regex: /firebaseConfig\s*=\s*\{[^}]*apiKey[^}]*\}/gs },
  { name: 'NPM Token',           severity: 'high',     regex: /npm_[A-Za-z0-9]{36}/g },
  { name: 'Hardcoded Password',  severity: 'high',     regex: /password\s*[:=]\s*["'][^"']{6,}["']/gi },
  { name: 'Hardcoded Secret',    severity: 'high',     regex: /secret\s*[:=]\s*["'][^"']{6,}["']/gi },
  { name: 'Bearer Token',        severity: 'high',     regex: /bearer\s+[A-Za-z0-9\-_=+\/]{20,}/gi },
  { name: 'Mailgun Key',         severity: 'high',     regex: /key-[0-9a-zA-Z]{32}/g },
  { name: 'Telegram Bot Token',  severity: 'high',     regex: /[0-9]{9}:[A-Za-z0-9_\-]{35}/g },
  { name: 'Cloudinary URL',      severity: 'high',     regex: /cloudinary:\/\/[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z]+/g },
  { name: 'Redis URI',           severity: 'high',     regex: /redis:\/\/[^:]+:[^@]+@[^\s"'`]+/gi },
  { name: 'Stripe Publishable',  severity: 'medium',   regex: /pk_live_[0-9a-zA-Z]{24}/g },
  { name: 'API Key Generic',     severity: 'medium',   regex: /api[_-]?key\s*[:=]\s*["'][^"']{8,}["']/gi },
];

// ══════════════════════════════════════════════════════════════
//  FIX GUIDES
// ══════════════════════════════════════════════════════════════
const FIX_GUIDES = {
  'AWS Access Key': {
    what: 'Amazon AWS credential. Anyone with this key can access your AWS account, create resources and run huge bills on your account.',
    steps: [
      'Go to https://console.aws.amazon.com/iam',
      'Click your username at top right then click Security credentials',
      'Under Access keys section, find the exposed key',
      'Click Deactivate then click Delete',
      'Click Create access key to generate a new one',
      'Add to your .env file:  AWS_ACCESS_KEY_ID=your_new_key',
      'Use in your code as:  process.env.AWS_ACCESS_KEY_ID',
      'Add .env to your .gitignore file immediately',
    ],
  },
  'GitHub Token': {
    what: 'GitHub Personal Access Token. Attacker can read, clone and push to all your repositories including private ones.',
    steps: [
      'Go to https://github.com/settings/tokens',
      'Find the exposed token in the list and click Delete',
      'Click Generate new token',
      'Select only the minimum permissions you actually need',
      'Add to .env:  GITHUB_TOKEN=your_new_token',
      'Use in code:  process.env.GITHUB_TOKEN',
    ],
  },
  'OpenAI API Key': {
    what: 'OpenAI API key. Attacker can use your credit quota and run up large billing charges on your OpenAI account.',
    steps: [
      'Go to https://platform.openai.com/api-keys',
      'Click the trash icon next to the exposed key to delete it',
      'Click Create new secret key',
      'Add to .env:  OPENAI_API_KEY=your_new_key',
      'Use in code:  process.env.OPENAI_API_KEY',
    ],
  },
  'MongoDB URI': {
    what: 'MongoDB database connection string with credentials. Attacker can read, edit or completely delete your database.',
    steps: [
      'Log in to MongoDB Atlas at https://cloud.mongodb.com',
      'Go to Database Access in the left sidebar',
      'Find the exposed user and click Edit',
      'Click Edit Password and change it immediately',
      'Update your .env:  MONGODB_URI=mongodb+srv://user:newpass@cluster.mongodb.net/db',
      'Use in code:  process.env.MONGODB_URI',
    ],
  },
  'Stripe Secret Key': {
    what: 'Stripe secret API key. Attacker can create charges, steal customer data and make transfers from your Stripe account.',
    steps: [
      'Go to https://dashboard.stripe.com/apikeys',
      'Click Roll key next to the exposed secret key',
      'Confirm to generate a new key',
      'Add to .env:  STRIPE_SECRET_KEY=your_new_key',
      'Use in code:  process.env.STRIPE_SECRET_KEY',
    ],
  },
  'Private Key': {
    what: 'Private cryptographic key found in code. Can be used to decrypt your data or impersonate your server identity.',
    steps: [
      'Revoke this key from the service that issued it immediately',
      'Generate a new key pair using ssh-keygen or openssl',
      'Store the private key path in .env:  PRIVATE_KEY_PATH=/path/to/key',
      'Never commit private key files to git',
      'Add the key file pattern to .gitignore:  *.pem, *.key, id_rsa',
    ],
  },
  'Hardcoded Password': {
    what: 'Plain-text password found directly in source code. Anyone with access to your codebase can steal and use these credentials.',
    steps: [
      'Change this password immediately in the target database or service',
      'Remove the hardcoded value from your source code',
      'Add to .env:  DB_PASSWORD=your_new_password',
      'Use in code:  process.env.DB_PASSWORD',
      'Make sure .env is listed in your .gitignore file',
    ],
  },
};

function getFixGuide(patternName) {
  return FIX_GUIDES[patternName] || {
    what: `Sensitive credential detected (${patternName}). Exposing this may allow unauthorized access to your systems or services.`,
    steps: [
      'Rotate or revoke this credential immediately in the service dashboard',
      'Remove the hardcoded value from your source code',
      'Add to your .env file:  VARIABLE_NAME=your_value',
      'Reference it in code as:  process.env.VARIABLE_NAME',
      'Make sure your .env file is listed in .gitignore',
    ],
  };
}

// ══════════════════════════════════════════════════════════════
//  SCANNER CORE
// ══════════════════════════════════════════════════════════════
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'out',
  'coverage', 'vendor', '__pycache__', '.idea', '.vscode',
  'tmp', 'temp', 'logs', '.cache',
]);

const SKIP_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp4', '.mp3', '.wav', '.avi', '.mov',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.pdf', '.docx', '.xlsx', '.pptx',
  '.lock', '.bin', '.exe', '.dll', '.so', '.dylib',
  '.map',
]);

function scanFile(filePath) {
  const results = [];
  let content;

  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return results; // skip files over 2MB
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return results;
  }

  const lines = content.split('\n');

  for (const pattern of PATTERNS) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = re.exec(content)) !== null) {
      const lineNum  = content.substring(0, match.index).split('\n').length;
      const lineText = (lines[lineNum - 1] || '').trim();
      const fix      = getFixGuide(pattern.name);

      results.push({
        id:         Date.now().toString(36) + Math.random().toString(36).substring(2, 8),
        file:       filePath,
        line:       lineNum,
        type:       pattern.name,
        severity:   pattern.severity,
        match:      match[0].length > 80 ? match[0].substring(0, 80) + '...' : match[0],
        lineText:   lineText.substring(0, 150),
        what:       fix.what,
        fixSteps:   fix.steps,
        status:     'pending',
        detectedAt: new Date().toISOString(),
      });
    }
  }

  return results;
}

function scanDirectory(dirPath) {
  const allResults = [];

  function walk(currentPath) {
    let entries;
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;

      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTS.has(ext)) continue;

      allResults.push(...scanFile(fullPath));
    }
  }

  walk(dirPath);
  return allResults;
}

// ══════════════════════════════════════════════════════════════
//  TERMINAL OUTPUT
// ══════════════════════════════════════════════════════════════
const C = {
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  green:  '\x1b[32m',
  cyan:   '\x1b[36m',
  blue:   '\x1b[34m',
  bold:   '\x1b[1m',
  reset:  '\x1b[0m',
};

function line() {
  console.log(`${C.cyan}${C.bold}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}`);
}

// ══════════════════════════════════════════════════════════════
//  MAIN
// ══════════════════════════════════════════════════════════════
const targetArg = process.argv[2];

if (!targetArg) {
  console.log(`\n${C.bold}${C.cyan}  Secret Scanner${C.reset}`);
  console.log(`  Usage: node scan.js <folder-path>\n`);
  console.log(`  Examples:`);
  console.log(`    node scan.js .`);
  console.log(`    node scan.js ./my-project`);
  console.log(`    node scan.js C:\\Users\\YourName\\project\n`);
  process.exit(0);
}

const fullPath = path.resolve(targetArg);

if (!fs.existsSync(fullPath)) {
  console.log(`\n${C.red}  Error: Path does not exist — ${fullPath}${C.reset}\n`);
  process.exit(1);
}

console.log(`\n`);
line();
console.log(`${C.bold}${C.cyan}    SECRET SCANNER${C.reset}`);
line();
console.log(`  Scanning: ${C.bold}${fullPath}${C.reset}\n`);

const t0      = Date.now();
const results = scanDirectory(fullPath);
const elapsed = ((Date.now() - t0) / 1000).toFixed(2);

if (results.length === 0) {
  console.log(`  ${C.green}${C.bold}No secrets found. Your project looks clean!${C.reset}`);
  console.log(`  Time: ${elapsed}s\n`);
  process.exit(0);
}

// Print each finding
for (const r of results) {
  let badge;
  if      (r.severity === 'critical') badge = `${C.bold}${C.red}  [CRITICAL]${C.reset}`;
  else if (r.severity === 'high')     badge = `${C.bold}${C.yellow}  [HIGH    ]${C.reset}`;
  else                                 badge = `${C.bold}${C.blue}  [MEDIUM  ]${C.reset}`;

  console.log(`${badge}  ${C.bold}${r.type}${C.reset}`);
  console.log(`           File : ${C.cyan}${r.file}${C.reset}`);
  console.log(`           Line : ${r.line}`);
  console.log(`           Found: ${C.red}${r.match}${C.reset}`);
  console.log('');
}

// Summary
const critCount = results.filter(r => r.severity === 'critical').length;
const highCount = results.filter(r => r.severity === 'high').length;
const medCount  = results.filter(r => r.severity === 'medium').length;

line();
console.log(`  ${C.bold}SUMMARY${C.reset}`);
line();
console.log(`  Total    : ${C.bold}${results.length}${C.reset}`);
console.log(`  Critical : ${C.red}${C.bold}${critCount}${C.reset}`);
console.log(`  High     : ${C.yellow}${C.bold}${highCount}${C.reset}`);
console.log(`  Medium   : ${C.blue}${C.bold}${medCount}${C.reset}`);
console.log(`  Time     : ${elapsed}s`);

// ── Save results.json ──────────────────────────────────────────
const outFile = path.join(__dirname, 'results.json');
let existing  = [];
try {
  existing = JSON.parse(fs.readFileSync(outFile, 'utf8'));
} catch {
  existing = [];
}

let newCount = 0;
for (const r of results) {
  const dup = existing.some(
    e => e.file === r.file && e.line === r.line && e.type === r.type
  );
  if (!dup) {
    existing.push(r);
    newCount++;
  }
}

fs.writeFileSync(outFile, JSON.stringify(existing, null, 2));

console.log(`\n  ${C.green}Saved to results.json (${newCount} new leak${newCount !== 1 ? 's' : ''} added)${C.reset}`);
console.log(`  ${C.green}To view dashboard: node server.js  →  http://localhost:3000${C.reset}\n`);