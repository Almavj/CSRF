const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

// --- In-memory user store ---
const users = {};
const sessions = {};
const auditLog = [];

// --- Challenge definitions with flags ---
const challenges = [
  {
    id: 1,
    name: 'Profile Hijack',
    difficulty: 'easy',
    endpoint: 'POST /profile/update-name',
    description: 'Change another user\'s display name without their knowledge.',
    hint: 'After changing the name, view the page source (Ctrl+U). Look for HTML comments.',
    lesson: 'CSRF tokens are essential for state-changing operations. A form without a token is wide open.',
    flag: 'FLAG{n0_t0k3n_n0_pr0t3ct10n_pr0f1l3_h1j4ck3d}'
  },
  {
    id: 2,
    name: 'Email Takeover',
    difficulty: 'medium',
    endpoint: 'POST /settings/update-email',
    description: 'Change another user\'s email address. The form has a CSRF token, but... is it actually secure?',
    hint: 'Bypass the token with any value matching csrf- followed by digits. Then view source on the response page.',
    lesson: 'Predictable or pattern-based tokens are no better than no token at all.',
    flag: 'FLAG{w34k_t0k3n_pr3d1ct4bl3_3m41l_t4k30v3r}'
  },
  {
    id: 3,
    name: 'Password Reset',
    difficulty: 'hard',
    endpoint: 'POST /security/change-password',
    description: 'Force a password change on another user\'s account. The double-submit cookie pattern should be secure... or is it?',
    hint: 'Set your own csrf_double_submit cookie (httpOnly=false, sameSite=none). Match it in the POST body. View source after success.',
    lesson: 'Double-submit cookies must be server-generated and stored server-side. Client-readable cookies can be forged.',
    flag: 'FLAG{d0ubl3_submit_c00k13_c4n_b3_f0rg3d}'
  },
  {
    id: 4,
    name: 'Silent Transfer',
    difficulty: 'expert',
    endpoint: 'POST /api/transfer',
    description: 'Make another user send money to your account. The API checks Content-Type, but can you bypass it?',
    hint: 'Use text/plain Content-Type with a JSON string body. The API response contains the flag.',
    lesson: 'Content-Type restrictions alone cannot prevent CSRF. Use proper tokens and validate Origin headers.',
    flag: 'FLAG{t3xt_pl41n_c0nt3nt_typ3_byp4ss3d}'
  },
  {
    id: 5,
    name: 'Privilege Escalation',
    difficulty: 'master',
    endpoint: 'POST /admin/promote',
    description: 'Promote yourself to admin. The admin panel has Referer checking, but is it checked before or after the action?',
    hint: 'The Referer check code exists but has no return statement. Submit the form cross-origin. View source on the admin page response.',
    lesson: 'Referer/Origin headers are advisory at best. Never rely on them as a sole CSRF defense.',
    flag: 'FLAG{r3f3r3r_h34d3r_1s_n0t_s3cur3}'
  },
  {
    id: 6,
    name: 'The Silent Disable',
    difficulty: 'legendary',
    endpoint: 'GET /api/2fa/disable',
    description: 'Disable 2FA on any account without them knowing. The 2FA toggle uses GET requests...',
    hint: 'Use an img tag or iframe to trigger the GET request. The JSON response contains the flag.',
    lesson: 'GET requests must NEVER cause state changes. Use POST with CSRF tokens for all mutations.',
    flag: 'FLAG{g3t_r3qu3st_sh0uld_n0t_ch4ng3_st4t3}'
  },
  {
    id: 7,
    name: 'Full Account Takeover',
    difficulty: 'legendary',
    endpoint: 'Chained attack',
    description: 'Chain multiple vulnerabilities to achieve full account takeover of the admin user. Get the secret note.',
    hint: 'Change admin email (Level 2), then reset admin password (Level 3), then login as admin. View source on the dashboard.',
    lesson: 'Individual vulnerabilities become critical when chained. Defense in depth is mandatory.',
    flag: 'FLAG{ch41n3d_csrf_fu11_4cc0unt_t4k30v3r}'
  }
];

// --- Per-user challenge progress ---
// Structure: { username: { 1: { solved: true, flag: '...' }, 2: { solved: false }, ... } }
const challengeProgress = {};

// Create default admin user
const adminHash = bcrypt.hashSync('admin123', 10);
users['admin'] = {
  id: 'usr_admin',
  username: 'admin',
  password: adminHash,
  email: 'admin@csrf.local',
  displayName: 'System Admin',
  role: 'admin',
  balance: 100000,
  transfers: [],
  twoFactorEnabled: false,
  apiKeys: [],
  secretNote: 'FLAG{ch41n3d_csrf_fu11_4cc0unt_t4k30v3r}',
  createdAt: '2024-01-01T00:00:00Z'
};

// Create regular test user
const userHash = bcrypt.hashSync('password123', 10);
users['user'] = {
  id: 'usr_user',
  username: 'user',
  password: userHash,
  email: 'user@csrf.local',
  displayName: 'Regular User',
  role: 'user',
  balance: 5000,
  transfers: [],
  twoFactorEnabled: false,
  apiKeys: [],
  secretNote: 'FLAG{n0_t0k3n_n0_pr0t3ct10n_pr0f1l3_h1j4ck3d}',
  createdAt: '2024-06-15T00:00:00Z'
};

// --- Middleware ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'csrf-training-secret-key-do-not-use-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 3600000,
    sameSite: 'lax'
  }
}));

// --- Request logger middleware ---
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const entry = {
    timestamp,
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    origin: req.get('Origin') || 'same-origin',
    referer: req.get('Referer') || 'none',
    cookies: req.cookies
  };
  auditLog.push(entry);
  if (auditLog.length > 500) auditLog.shift();
  next();
});

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    const user = users[req.session.userId];
    if (user) {
      req.user = user;
      return next();
    }
  }
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  res.status(403).render('error', {
    title: 'Access Denied',
    message: 'Admin privileges required.',
    code: 403,
    user: req.user || null
  });
}

// --- Routes ---

// Landing page
app.get('/', (req, res) => {
  res.render('index', {
    title: 'CSRF - Cross-Site Request Forgery Training Platform',
    user: req.session ? users[req.session.userId] : null
  });
});

// --- VULN LEVEL 1: Login page - session fixation ---
// The app accepts a session token via query parameter (session fixation vuln)
app.get('/login', (req, res) => {
  // VULN: Session fixation - accepts session ID from URL
  if (req.query.sid) {
    req.session.regenerate(() => {
      req.session.userId = 'user';
      res.redirect('/dashboard');
    });
    return;
  }
  res.render('login', {
    title: 'Login - CSRF',
    error: null,
    user: null
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.regenerate((err) => {
      req.session.userId = username;
      res.redirect('/dashboard');
    });
  } else {
    res.render('login', {
      title: 'Login - CSRF',
      error: 'Invalid credentials. Try: admin/admin123 or user/password123',
      user: null
    });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// --- Dashboard ---
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', {
    title: 'Dashboard - CSRF',
    user: req.user,
    recentTransfers: req.user.transfers.slice(-5).reverse(),
    flag: req.user.role === 'admin' ? challenges[6].flag : null
  });
});

// --- VULN LEVEL 2: Profile update - NO CSRF PROTECTION AT ALL ---
// This is the easiest vulnerability: no token, no check, just raw POST
app.get('/profile', requireAuth, (req, res) => {
  res.render('profile', {
    title: 'Profile Settings - CSRF',
    user: req.user,
    success: null,
    error: null
  });
});

// VULNERABLE: No CSRF token validation. Attacker can submit form from external site.
app.post('/profile/update-name', requireAuth, (req, res) => {
  const { displayName } = req.body;
  if (displayName && displayName.length > 0 && displayName.length < 50) {
    req.user.displayName = displayName;
    res.render('profile', {
      title: 'Profile Settings - CSRF',
      user: req.user,
      success: 'Display name updated successfully!',
      error: null,
      flag: challenges[0].flag
    });
  } else {
    res.render('profile', {
      title: 'Profile Settings - CSRF',
      user: req.user,
      success: null,
      error: 'Invalid display name.',
      flag: null
    });
  }
});

// --- VULN LEVEL 3: Email change - flawed CSRF token ---
// Token is generated but validation compares against a hardcoded weak secret
app.get('/settings', requireAuth, (req, res) => {
  const csrfToken = generateWeakToken(req.user.id);
  res.render('settings', {
    title: 'Account Settings - CSRF',
    user: req.user,
    csrfToken: csrfToken,
    success: null,
    error: null
  });
});

// VULNERABLE: Token validation is weak - uses predictable pattern
app.post('/settings/update-email', requireAuth, (req, res) => {
  const { email, csrf_token } = req.body;

  // VULN: Token check is bypassed if the token matches the pattern "csrf-" + any number
  const tokenValid = csrf_token && /^csrf-\d+$/.test(csrf_token);

  if (!tokenValid) {
    res.render('settings', {
      title: 'Account Settings - CSRF',
      user: req.user,
      csrfToken: generateWeakToken(req.user.id),
      success: null,
      error: 'Invalid CSRF token.'
    });
    return;
  }

  if (email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    req.user.email = email;
    res.render('settings', {
      title: 'Account Settings - CSRF',
      user: req.user,
      csrfToken: generateWeakToken(req.user.id),
      success: 'Email updated successfully!',
      error: null,
      flag: challenges[1].flag
    });
  } else {
    res.render('settings', {
      title: 'Account Settings - CSRF',
      user: req.user,
      csrfToken: generateWeakToken(req.user.id),
      success: null,
      error: 'Invalid email address.',
      flag: null
    });
  }
});

// --- VULN LEVEL 4: Password change - double-submit cookie (flawed) ---
app.get('/security', requireAuth, (req, res) => {
  const token = uuidv4();
  res.cookie('csrf_double_submit', token, {
    httpOnly: false,
    sameSite: 'none',
    secure: false
  });
  res.render('security', {
    title: 'Security Settings - CSRF',
    user: req.user,
    csrfToken: token,
    success: null,
    error: null
  });
});

// VULNERABLE: Double-submit cookie pattern. Server checks that cookie == body param,
// but attacker can SET their own cookie from a cross-origin form? No - httpOnly is false
// but sameSite=none + secure=false means cookies ARE sent cross-origin.
// The vuln: attacker sets their own cookie value AND sends it in the body.
app.post('/security/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword, csrf_token } = req.body;
  const cookieToken = req.cookies['csrf_double_submit'];

  // VULN: Only checks that cookie and body match, not that it's a server-generated token
  if (!cookieToken || cookieToken !== csrf_token) {
    res.render('security', {
      title: 'Security Settings - CSRF',
      user: req.user,
      csrfToken: uuidv4(),
      success: null,
      error: 'CSRF token mismatch.'
    });
    return;
  }

  if (!bcrypt.compareSync(currentPassword, req.user.password)) {
    res.render('security', {
      title: 'Security Settings - CSRF',
      user: req.user,
      csrfToken: uuidv4(),
      success: null,
      error: 'Current password is incorrect.'
    });
    return;
  }

  if (newPassword && newPassword.length >= 8) {
    req.user.password = bcrypt.hashSync(newPassword, 10);
    res.render('security', {
      title: 'Security Settings - CSRF',
      user: req.user,
      csrfToken: uuidv4(),
      success: 'Password changed successfully!',
      error: null,
      flag: challenges[2].flag
    });
  } else {
    res.render('security', {
      title: 'Security Settings - CSRF',
      user: req.user,
      csrfToken: uuidv4(),
      success: null,
      error: 'Password must be at least 8 characters.'
    });
  }
});

// --- VULN LEVEL 5: Fund transfer - JSON API with CORS misconfiguration ---
app.get('/transfer', requireAuth, (req, res) => {
  res.render('transfer', {
    title: 'Fund Transfer - CSRF',
    user: req.user,
    success: null,
    error: null
  });
});

// VULNERABLE: API endpoint accepts JSON, but CORS allows any origin with credentials
// Content-Type check can be bypassed with text/plain
app.post('/api/transfer', requireAuth, (req, res) => {
  const contentType = req.get('Content-Type') || '';

  let amount, toAccount, memo;

  // VULN: Accepts text/plain with JSON body (bypasses content-type restrictions)
  if (contentType.includes('application/json') || contentType.includes('text/plain')) {
    try {
      let body = req.body;
      if (typeof body === 'string') {
        body = JSON.parse(body);
      }
      amount = body.amount;
      toAccount = body.toAccount;
      memo = body.memo || '';
    } catch (e) {
      // If body-parser already parsed it
      amount = req.body.amount;
      toAccount = req.body.toAccount;
      memo = req.body.memo || '';
    }
  } else {
    amount = req.body.amount;
    toAccount = req.body.toAccount;
    memo = req.body.memo || '';
  }

  amount = parseFloat(amount);

  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  if (!toAccount) {
    return res.status(400).json({ error: 'Invalid destination account' });
  }
  if (amount > req.user.balance) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }

  req.user.balance -= amount;
  const transfer = {
    id: uuidv4(),
    from: req.user.username,
    to: toAccount,
    amount,
    memo,
    timestamp: new Date().toISOString()
  };
  req.user.transfers.push(transfer);

  res.json({
    success: true,
    message: `$${amount.toFixed(2)} transferred to ${toAccount}`,
    transfer,
    newBalance: req.user.balance,
    flag: challenges[3].flag
  });
});

// --- VULN LEVEL 6: Admin panel - uses Referer header check (bypassable) ---
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  // Init progress for all users
  Object.keys(users).forEach(u => initProgress(u));
  const allProgress = {};
  Object.keys(users).forEach(u => {
    const p = challengeProgress[u];
    const solved = Object.values(p).filter(v => v.solved).length;
    allProgress[u] = { total: challenges.length, solved, percentage: Math.round((solved / challenges.length) * 100) };
  });
  res.render('admin', {
    title: 'Admin Panel - CSRF',
    user: req.user,
    users: Object.values(users),
    auditLog: auditLog.slice(-50).reverse(),
    challenges: challenges,
    allProgress: allProgress,
    success: null,
    error: null
  });
});

// VULNERABLE: Only checks Referer header for admin actions, not CSRF token
app.post('/admin/promote', requireAuth, (req, res) => {
  // VULN: Relies on Referer header which can be spoofed
  const referer = req.get('Referer') || '';
  if (!referer.includes('/admin')) {
    // VULN: But it does the check AFTER processing the request logic
    // and the error message leaks information
  }

  const { targetUser, newRole } = req.body;

  if (targetUser && users[targetUser]) {
    users[targetUser].role = newRole || 'admin';

    Object.keys(users).forEach(u => initProgress(u));
    const allProgress = {};
    Object.keys(users).forEach(u => {
      const p = challengeProgress[u];
      const solved = Object.values(p).filter(v => v.solved).length;
      allProgress[u] = { total: challenges.length, solved, percentage: Math.round((solved / challenges.length) * 100) };
    });

    res.render('admin', {
      title: 'Admin Panel - CSRF',
      user: req.user,
      users: Object.values(users),
      auditLog: auditLog.slice(-50).reverse(),
      challenges: challenges,
      allProgress: allProgress,
      success: `User ${targetUser} has been promoted to ${newRole || 'admin'}.`,
      error: null,
      flag: challenges[4].flag
    });
  } else {
    Object.keys(users).forEach(u => initProgress(u));
    const allProgress = {};
    Object.keys(users).forEach(u => {
      const p = challengeProgress[u];
      const solved = Object.values(p).filter(v => v.solved).length;
      allProgress[u] = { total: challenges.length, solved, percentage: Math.round((solved / challenges.length) * 100) };
    });

    res.render('admin', {
      title: 'Admin Panel - CSRF',
      user: req.user,
      users: Object.values(users),
      auditLog: auditLog.slice(-50).reverse(),
      challenges: challenges,
      allProgress: allProgress,
      success: null,
      error: 'User not found.'
    });
  }
});

// VULNERABLE: Delete user - token in HTML comment, leaked via Referer
app.post('/admin/delete-user', requireAuth, requireAdmin, (req, res) => {
  const { targetUser } = req.body;

  if (targetUser && users[targetUser] && targetUser !== 'admin') {
    delete users[targetUser];

    Object.keys(users).forEach(u => initProgress(u));
    const allProgress = {};
    Object.keys(users).forEach(u => {
      const p = challengeProgress[u];
      const solved = Object.values(p).filter(v => v.solved).length;
      allProgress[u] = { total: challenges.length, solved, percentage: Math.round((solved / challenges.length) * 100) };
    });

    res.render('admin', {
      title: 'Admin Panel - CSRF',
      user: req.user,
      users: Object.values(users),
      auditLog: auditLog.slice(-50).reverse(),
      challenges: challenges,
      allProgress: allProgress,
      success: `User ${targetUser} has been deleted.`,
      error: null
    });
  } else {
    Object.keys(users).forEach(u => initProgress(u));
    const allProgress = {};
    Object.keys(users).forEach(u => {
      const p = challengeProgress[u];
      const solved = Object.values(p).filter(v => v.solved).length;
      allProgress[u] = { total: challenges.length, solved, percentage: Math.round((solved / challenges.length) * 100) };
    });

    res.render('admin', {
      title: 'Admin Panel - CSRF',
      user: req.user,
      users: Object.values(users),
      auditLog: auditLog.slice(-50).reverse(),
      challenges: challenges,
      allProgress: allProgress,
      success: null,
      error: 'Cannot delete this user.'
    });
  }
});

// --- Hidden API endpoint (not linked anywhere) ---
// VULN LEVEL 7: Hidden API key generation - vulnerable to CSRF via script tags
app.post('/api/generate-key', requireAuth, (req, res) => {
  const apiKey = 'csrf-' + uuidv4();
  req.user.apiKeys.push({ key: apiKey, created: new Date().toISOString() });
  res.json({ success: true, apiKey });
});

// VULN: This endpoint has no CSRF protection AND no Content-Type check
// An attacker can submit a form with method=POST action=/api/key-revoke
app.post('/api/key-revoke', requireAuth, (req, res) => {
  const { key } = req.body;
  req.user.apiKeys = req.user.apiKeys.filter(k => k.key !== key);
  res.json({ success: true, message: 'Key revoked' });
});

// --- Hidden endpoint: enable 2FA ---
// VULN LEVEL 8: No CSRF protection, uses GET for state change
app.get('/api/2fa/enable', requireAuth, (req, res) => {
  // VULN: GET request changes state - classic CSRF via img tag
  req.user.twoFactorEnabled = true;
  req.user.twoFactorSecret = 'CSRF' + uuidv4().slice(0, 8).toUpperCase();
  res.json({
    success: true,
    message: 'Two-factor authentication enabled',
    secret: req.user.twoFactorSecret,
    flag: challenges[5].flag
  });
});

app.get('/api/2fa/disable', requireAuth, (req, res) => {
  // VULN: Same as above - GET changes state
  req.user.twoFactorEnabled = false;
  res.json({ success: true, message: 'Two-factor authentication disabled', flag: challenges[5].flag });
});

// --- Hidden page: challenge walkthrough (hint system) ---
app.get('/challenges', requireAuth, (req, res) => {
  initProgress(req.user.username);
  const progress = challengeProgress[req.user.username];
  res.render('challenges', {
    title: 'CSRF Challenges',
    user: req.user,
    challenges: challenges,
    progress: progress
  });
});

// --- Audit log viewer (admin only but log leaks info) ---
app.get('/api/audit', requireAuth, (req, res) => {
  // VULN: Any authenticated user can read audit logs (broken access control)
  res.json({ logs: auditLog.slice(-100) });
});

// --- Debug endpoint (hidden) ---
// VULN: Leaks server internals
app.get('/api/debug/config', (req, res) => {
  res.json({
    sessionSecret: 'csrf-training-secret-key-do-not-use-in-production',
    serverTime: new Date().toISOString(),
    nodeEnv: process.env.NODE_ENV || 'development',
    uptime: process.uptime()
  });
});

// --- Targets / Flag Submission System ---
function initProgress(username) {
  if (!challengeProgress[username]) {
    challengeProgress[username] = {};
    challenges.forEach(c => {
      challengeProgress[username][c.id] = { solved: false, flag: null, solvedAt: null };
    });
  }
}

// Targets page
app.get('/targets', requireAuth, (req, res) => {
  initProgress(req.user.username);
  const progress = challengeProgress[req.user.username];
  res.render('targets', {
    title: 'Learning Targets - CSRF',
    user: req.user,
    challenges: challenges,
    progress: progress,
    success: null,
    error: null
  });
});

// Submit a flag
app.post('/api/submit-flag', requireAuth, (req, res) => {
  initProgress(req.user.username);
  const { challengeId, flag } = req.body;
  const id = parseInt(challengeId);
  const challenge = challenges.find(c => c.id === id);

  if (!challenge) {
    return res.status(400).json({ success: false, error: 'Invalid challenge ID.' });
  }

  if (challengeProgress[req.user.username][id].solved) {
    return res.json({ success: true, message: 'Already solved!', alreadySolved: true });
  }

  if (flag && flag.trim() === challenge.flag) {
    challengeProgress[req.user.username][id] = {
      solved: true,
      flag: challenge.flag,
      solvedAt: new Date().toISOString()
    };
    return res.json({ success: true, message: `Correct! Challenge ${id} completed.` });
  }

  return res.json({ success: false, error: 'Incorrect flag. Try again!' });
});

// Get progress for current user
app.get('/api/progress', requireAuth, (req, res) => {
  initProgress(req.user.username);
  const progress = challengeProgress[req.user.username];
  const total = challenges.length;
  const solved = Object.values(progress).filter(p => p.solved).length;
  res.json({ total, solved, progress, percentage: Math.round((solved / total) * 100) });
});

// Get all users' progress (admin only)
app.get('/api/progress/all', requireAuth, requireAdmin, (req, res) => {
  Object.keys(users).forEach(u => initProgress(u));
  const allProgress = {};
  Object.keys(users).forEach(u => {
    const p = challengeProgress[u];
    const solved = Object.values(p).filter(v => v.solved).length;
    allProgress[u] = { total: challenges.length, solved, percentage: Math.round((solved / challenges.length) * 100) };
  });
  res.json(allProgress);
});

// --- 404 ---
app.use((req, res) => {
  res.status(404).render('error', {
    title: '404 - Not Found',
    message: 'The page you are looking for does not exist.',
    code: 404,
    user: req.session ? users[req.session.userId] : null
  });
});

// --- Helper functions ---
function generateWeakToken(userId) {
  // VULN: Predictable token generation - just "csrf-" + counter based on timestamp
  return 'csrf-' + Math.floor(Date.now() / 10000);
}

// --- Start server ---
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██████╗ ██████╗ ██████╗ ███████╗                          ║
║   ██╔════╝██╔═══██╗██╔══██╗██╔════╝                          ║
║   ██║     ██║   ██║██║  ██║█████╗                            ║
║   ██║     ██║   ██║██║  ██║██╔══╝                            ║
║   ╚██████╗╚██████╔╝██████╔╝███████╗                          ║
║    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝                          ║
║                                                              ║
║   Cross-Site Request Forgery Training Platform               ║
║                                                              ║
║   Server running on http://localhost:${PORT}                   ║
║                                                              ║
║   Login credentials:                                         ║
║     Admin:  admin / admin123                                 ║
║     User:   user  / password123                              ║
║                                                              ║
║   WARNING: This application is intentionally vulnerable.     ║
║   Do NOT deploy to a public network.                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
