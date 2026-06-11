require('dotenv').config();

const express      = require('express');
const fs           = require('fs');
const path         = require('path');
const crypto       = require('crypto');
const os           = require('os');
const { execSync } = require('child_process');
const mongoose     = require('mongoose');
const jwt          = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_this';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════════════════════════
//  MONGODB CONNECTION
// ══════════════════════════════════════════════════════════════
const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
  console.error('  ❌  Missing MONGO_URI in environment variables');
  process.exit(1);
}

mongoose.connect(mongoURI)
  .then(() => console.log('  ✅  MongoDB Connected'))
  .catch(err => { console.error('  ❌  MongoDB Error:', err.message); process.exit(1); });

// ══════════════════════════════════════════════════════════════
//  MONGOOSE SCHEMAS
// ══════════════════════════════════════════════════════════════
const userSchema = new mongoose.Schema({
  uid:       { type: String, required: true },
  username:  { type: String, unique: true, required: true },
  password:  { type: String, required: true },
  createdAt: { type: String },
});
const User = mongoose.model('User', userSchema);

const leakSchema = new mongoose.Schema({
  lid:        { type: String, required: true, unique: true },
  file:       String,
  line:       Number,
  type:       String,
  severity:   String,
  match:      String,
  lineText:   String,
  what:       String,
  fixSteps:   [String],
  status:     { type: String, default: 'pending' },
  detectedAt: String,
  updatedAt:  String,
  updatedBy:  String,
});
const Leak = mongoose.model('Leak', leakSchema);

// ══════════════════════════════════════════════════════════════
//  AUTH HELPERS  — JWT based (works across multiple servers)
// ══════════════════════════════════════════════════════════════
function hashPw(pw) {
  return crypto.createHash('sha256').update('ss2024salt:' + pw).digest('hex');
}

function makeJWT(user) {
  return jwt.sign(
    { id: user.uid, username: user.username },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function auth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

// ══════════════════════════════════════════════════════════════
//  SCANNER PATTERNS
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

const FIX_GUIDES = {
  'AWS Access Key':     { what: 'Amazon AWS credential. Anyone with this key can access your AWS account and run up huge bills.', steps: ['Go to https://console.aws.amazon.com/iam', 'Click your username → Security credentials', 'Find the exposed key → Deactivate → Delete', 'Create a new access key', 'Add to .env:  AWS_ACCESS_KEY_ID=your_new_key', 'Use in code:  process.env.AWS_ACCESS_KEY_ID'] },
  'GitHub Token':       { what: 'GitHub Personal Access Token. Attacker can read/write all your repositories including private ones.', steps: ['Go to https://github.com/settings/tokens', 'Find and delete the exposed token', 'Generate new token with minimum required permissions', 'Add to .env:  GITHUB_TOKEN=your_new_token', 'Use in code:  process.env.GITHUB_TOKEN'] },
  'OpenAI API Key':     { what: 'OpenAI API key. Attacker can use your quota and run up large billing charges.', steps: ['Go to https://platform.openai.com/api-keys', 'Delete the exposed key', 'Create a new secret key', 'Add to .env:  OPENAI_API_KEY=your_new_key', 'Use in code:  process.env.OPENAI_API_KEY'] },
  'MongoDB URI':        { what: 'MongoDB connection string. Attacker can read, modify or delete your entire database.', steps: ['Log in to https://cloud.mongodb.com', 'Go to Database Access → Edit the user', 'Change the password immediately', 'Update .env:  MONGODB_URI=new_uri', 'Use in code:  process.env.MONGODB_URI'] },
  'Stripe Secret Key':  { what: 'Stripe secret key. Attacker can create charges and steal customer payment data.', steps: ['Go to https://dashboard.stripe.com/apikeys', 'Click Roll key next to the exposed key', 'Add to .env:  STRIPE_SECRET_KEY=your_new_key', 'Use in code:  process.env.STRIPE_SECRET_KEY'] },
  'Private Key':        { what: 'Private cryptographic key. Can decrypt your data or impersonate your server.', steps: ['Revoke this key from the issuing service immediately', 'Generate a new key pair', 'Store private key in environment variable or secrets manager', 'Add key files to .gitignore: *.pem, *.key'] },
  'Hardcoded Password': { what: 'Plain-text password in source code. Anyone with repo access can steal credentials.', steps: ['Change this password in the target service immediately', 'Remove the hardcoded value from your code', 'Add to .env:  DB_PASSWORD=your_new_password', 'Use in code:  process.env.DB_PASSWORD', 'Add .env to .gitignore'] },
};

function getFixGuide(name) {
  return FIX_GUIDES[name] || {
    what: `Sensitive credential detected (${name}). May allow unauthorized access to your systems.`,
    steps: ['Rotate or revoke this credential in the service dashboard immediately', 'Remove the hardcoded value from source code', 'Add to .env:  VARIABLE_NAME=value', 'Use in code:  process.env.VARIABLE_NAME', 'Add .env to .gitignore'],
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
  '.png','.jpg','.jpeg','.gif','.svg','.ico','.webp',
  '.woff','.woff2','.ttf','.eot','.mp4','.mp3','.wav',
  '.zip','.tar','.gz','.rar','.pdf','.lock','.bin',
  '.exe','.dll','.map',
]);

// These specific filenames are always skipped — lock files, scanner's own data files
const SKIP_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'results.json',
  'users.json',
  '.env',
  '.env.local',
  '.env.production',
]);

function scanFile(filePath) {
  const results = [];
  let content;
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return results;
    content = fs.readFileSync(filePath, 'utf8');
  } catch { return results; }

  const lines = content.split('\n');
  for (const p of PATTERNS) {
    const re = new RegExp(p.regex.source, p.regex.flags);
    let m;
    while ((m = re.exec(content)) !== null) {
      const lineNum = content.substring(0, m.index).split('\n').length;
      const fix = getFixGuide(p.name);
      results.push({
        lid:        crypto.randomBytes(8).toString('hex'),
        file:       filePath,
        line:       lineNum,
        type:       p.name,
        severity:   p.severity,
        match:      m[0].length > 80 ? m[0].substring(0, 80) + '...' : m[0],
        lineText:   (lines[lineNum - 1] || '').trim().substring(0, 150),
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
  const all = [];
  function walk(cur) {
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (SKIP_DIRS.has(e.name)) continue;
      if (SKIP_FILES.has(e.name)) continue;          // ← skip lock files & data files
      const full = path.join(cur, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (SKIP_EXTS.has(path.extname(e.name).toLowerCase())) continue;
      all.push(...scanFile(full));
    }
  }
  walk(dirPath);
  return all;
}

// ══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });
  if (username.trim().length < 3)
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  if (!/^[a-zA-Z0-9_]+$/.test(username.trim()))
    return res.status(400).json({ error: 'Username can only contain letters, numbers and underscores.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (password.length > 100)
    return res.status(400).json({ error: 'Password is too long.' });

  try {
    const existing = await User.findOne({ username: { $regex: new RegExp(`^${username.trim()}$`, 'i') } });
    if (existing)
      return res.status(400).json({ error: 'Username already taken. Please choose another.' });

    await User.create({
      uid:       crypto.randomBytes(8).toString('hex'),
      username:  username.trim(),
      password:  hashPw(password),
      createdAt: new Date().toISOString(),
    });
    res.json({ success: true, message: 'Account created! You can now sign in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Please enter username and password.' });

  try {
    const user = await User.findOne({
      username: { $regex: new RegExp(`^${username.trim()}$`, 'i') },
      password: hashPw(password),
    });
    if (!user) return res.status(401).json({ error: 'Incorrect username or password.' });

    const token = makeJWT(user);
    res.json({ success: true, token, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

app.post('/api/logout', auth, (req, res) => {
  // JWT is stateless — client just deletes the token
  res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════
//  SCAN ROUTE
// ══════════════════════════════════════════════════════════════
app.post('/api/scan', auth, async (req, res) => {
  const { target } = req.body || {};
  if (!target || !target.trim())
    return res.status(400).json({ error: 'Please provide a folder path or GitHub URL.' });

  const t = target.trim();
  let scanPath = null;
  let tempDir  = null;
  let isGitHub = false;

  if (t.includes('github.com/')) {
    isGitHub = true;
    try { execSync('git --version', { stdio: 'ignore' }); }
    catch { return res.status(500).json({ error: 'Git is not installed on this server.' }); }

    tempDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-'));
    scanPath = tempDir;

    try {
      execSync(`git clone --depth=1 "${t}" "${tempDir}"`, { stdio: 'ignore', timeout: 60000 });
    } catch {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
      return res.status(400).json({ error: 'Could not clone repository. Make sure the URL is correct and the repo is public.' });
    }
  } else {
    scanPath = path.resolve(t);
    if (!fs.existsSync(scanPath))
      return res.status(404).json({ error: `Folder not found: ${scanPath}` });
    if (!fs.statSync(scanPath).isDirectory())
      return res.status(400).json({ error: `That path is a file, not a folder.` });
  }

  let results = [];
  try {
    results = scanDirectory(scanPath);
  } finally {
    if (tempDir) { try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {} }
  }

  try {
    let added = 0;
    for (const r of results) {
      const dup = await Leak.findOne({ file: r.file, line: r.line, type: r.type });
      if (!dup) { await Leak.create(r); added++; }
    }

    const critical = results.filter(r => r.severity === 'critical').length;
    const high     = results.filter(r => r.severity === 'high').length;
    const medium   = results.filter(r => r.severity === 'medium').length;

    res.json({
      success: true,
      total:   results.length,
      added,
      critical, high, medium,
      source:  isGitHub ? 'github' : 'local',
      message: results.length === 0
        ? 'No secrets found! Your project looks clean.'
        : `Found ${results.length} secret(s) — ${critical} critical, ${high} high, ${medium} medium. ${added} new added to dashboard.`,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving results. Please try again.' });
  }
});

// ══════════════════════════════════════════════════════════════
//  LEAK ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/leaks', auth, async (req, res) => {
  try {
    const raw   = await Leak.find().lean();
    // Rename lid → id for frontend compatibility
    const leaks = raw.map(l => ({ ...l, id: l.lid }));
    res.json({ leaks });
  } catch { res.status(500).json({ error: 'Could not fetch leaks.' }); }
});

app.get('/api/stats', auth, async (req, res) => {
  try {
    const leaks    = await Leak.find().lean();
    const total    = leaks.length;
    const fixed    = leaks.filter(l => l.status === 'fixed').length;
    const ignored  = leaks.filter(l => l.status === 'ignored').length;
    const pending  = leaks.filter(l => l.status === 'pending').length;
    const critical = leaks.filter(l => l.severity === 'critical' && l.status === 'pending').length;
    const high     = leaks.filter(l => l.severity === 'high'     && l.status === 'pending').length;
    const medium   = leaks.filter(l => l.severity === 'medium'   && l.status === 'pending').length;

    let grade = 'A';
    if      (critical >= 1) grade = 'F';
    else if (high     >= 5) grade = 'D';
    else if (high     >= 2) grade = 'C';
    else if (high     >= 1) grade = 'B';
    else if (medium   >= 3) grade = 'B';

    res.json({ total, fixed, ignored, pending, critical, high, medium, grade });
  } catch { res.status(500).json({ error: 'Could not fetch stats.' }); }
});

app.patch('/api/leak/:id', auth, async (req, res) => {
  const { status } = req.body || {};
  if (!['fixed', 'ignored', 'pending'].includes(status))
    return res.status(400).json({ error: 'status must be: fixed | ignored | pending' });
  try {
    const leak = await Leak.findOne({ lid: req.params.id });
    if (!leak) return res.status(404).json({ error: 'Leak not found.' });
    leak.status    = status;
    leak.updatedAt = new Date().toISOString();
    leak.updatedBy = req.user.username;
    await leak.save();
    res.json({ success: true, leak: { ...leak.toObject(), id: leak.lid } });
  } catch { res.status(500).json({ error: 'Could not update leak.' }); }
});

app.delete('/api/leak/:id', auth, async (req, res) => {
  try {
    const result = await Leak.deleteOne({ lid: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Leak not found.' });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not delete leak.' }); }
});

app.delete('/api/leaks/clear', auth, async (req, res) => {
  try {
    await Leak.deleteMany({});
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Could not clear leaks.' }); }
});

// ══════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n  ┌───────────────────────────────────────────┐');
  console.log('  │        SECRET SCANNER DASHBOARD           │');
  console.log('  ├───────────────────────────────────────────┤');
  console.log(`  │   Open →  http://localhost:${PORT}          │`);
  console.log('  └───────────────────────────────────────────┘\n');
});