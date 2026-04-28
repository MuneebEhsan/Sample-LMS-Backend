'use strict';
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const { query } = require('../../db');

const hashToken = (raw) => crypto.createHash('sha256').update(raw).digest('hex');

// ── auth middleware — validates JWT + loads user role ─────────────────────────
async function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });

  const token = authHeader.slice(7);
  try {
    const payload   = jwt.verify(token, process.env.JWT_SECRET);
    const tokenHash = hashToken(token);

    // Validate session still exists
    const { rows: sessionRows } = await query(
      `SELECT id FROM sessions WHERE user_id=$1 AND token_hash=$2 AND expires_at > NOW()`,
      [payload.sub, tokenHash]
    );
    if (!sessionRows.length) return res.status(401).json({ error: 'Session expired or revoked' });

    // Load user + primary role
    const { rows: userRows } = await query(
      `SELECT u.id, u.tenant_id, u.status, u.email,
              u.first_name, u.last_name,
              array_agg(r.name) FILTER (WHERE r.name IS NOT NULL) AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r       ON r.id = ur.role_id
       WHERE u.id = $1
       GROUP BY u.id`,
      [payload.sub]
    );

    if (!userRows.length) return res.status(401).json({ error: 'User not found' });
    const user = userRows[0];

    if (user.status === 'suspended' || user.status === 'deleted')
      return res.status(403).json({ error: 'Account suspended or deleted' });

    req.user = {
      id:       user.id,
      tenantId: user.tenant_id,
      email:    user.email,
      name:     `${user.first_name || ''} ${user.last_name || ''}`.trim(),
      roles:    user.roles || [],
      role:     (user.roles || [])[0] || 'Student',   // primary role
    };
    req.tokenHash = tokenHash;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Token expired' });
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── requireRole — checks if user has at least one of the given roles ──────────
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    const hasRole = roles.some(r => (req.user.roles || []).includes(r));
    if (!hasRole)
      return res.status(403).json({ error: `Requires one of: ${roles.join(', ')}` });
    next();
  };
}

// ── tenantGuard — injects tenant context ──────────────────────────────────────
function tenantGuard(req, _res, next) {
  const tenantId = req.headers['x-tenant-id'];
  if (tenantId) req.tenantId = tenantId;
  else if (req.user?.tenantId) req.tenantId = req.user.tenantId;
  next();
}

// ── drmAuth — validates DRM short-lived tokens ────────────────────────────────
async function drmAuth(req, res, next) {
  const token = req.query.token || req.headers['x-drm-token'];
  if (!token) return res.status(401).json({ error: 'DRM token required' });

  try {
    // Verify JWT signature first
    jwt.verify(token, process.env.DRM_TOKEN_SECRET || process.env.JWT_SECRET);
  } catch {
    return res.status(403).json({ error: 'Invalid DRM token' });
  }

  const { rows } = await query(
    `SELECT * FROM drm_tokens WHERE token_hash=$1 AND expires_at > NOW() AND revoked=FALSE`,
    [hashToken(token)]
  );
  if (!rows.length) return res.status(403).json({ error: 'DRM token expired or revoked' });

  req.drmToken = rows[0];
  next();
}

module.exports = { auth, requireRole, tenantGuard, drmAuth };
