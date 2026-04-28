'use strict';
// ══════════════════════════════════════════════════════════════════════════════
// PHASE 1 — Authentication (routes + controller + service in one module file)
// Endpoints: register, login, 2FA, refresh, logout, OAuth, password reset
// ══════════════════════════════════════════════════════════════════════════════
const router      = require('express').Router();
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const speakeasy   = require('speakeasy');
const qrcode      = require('qrcode');
const crypto      = require('crypto');
const { v4: uuid }= require('uuid');
const { query }   = require('../../db');
const { auth }    = require('../../common/middleware/auth');
const { validate, rules } = require('../../common/validators/auth.validator');
const { sendEmail }= require('../../common/utils/mailer');
const { auditLog } = require('../../common/utils/audit');
const logger      = require('../../common/utils/logger');

// ── Helpers ───────────────────────────────────────────────────────────────────
const signJWT = (payload, secret, expiresIn) =>
  jwt.sign(payload, secret, { expiresIn });

const hashToken = (raw) =>
  crypto.createHash('sha256').update(raw).digest('hex');

async function findUserByEmail(email, tenantId = null) {
  const q = tenantId
    ? 'SELECT * FROM users WHERE email=$1 AND tenant_id=$2 LIMIT 1'
    : 'SELECT * FROM users WHERE email=$1 LIMIT 1';
  const params = tenantId ? [email, tenantId] : [email];
  const { rows } = await query(q, params);
  return rows[0] || null;
}

async function findUserById(id) {
  const { rows } = await query('SELECT * FROM users WHERE id=$1', [id]);
  return rows[0] || null;
}

async function getUserPublic(user) {
  const { rows: roleRows } = await query(
    `SELECT r.name FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = $1`, [user.id]
  );
  return {
    id:          user.id,
    email:       user.email,
    firstName:   user.first_name,
    lastName:    user.last_name,
    avatarUrl:   user.avatar_url,
    tenantId:    user.tenant_id,
    twoFaEnabled:user.two_fa_enabled,
    status:      user.status,
    roles:       roleRows.map(r => r.name),
    createdAt:   user.created_at,
  };
}

function issueTokenPair(userId, tenantId) {
  const access  = signJWT({ sub: userId, tid: tenantId }, process.env.JWT_SECRET, process.env.JWT_EXPIRES_IN || '7d');
  const refresh = signJWT({ sub: userId, tid: tenantId }, process.env.JWT_REFRESH_SECRET, process.env.JWT_REFRESH_EXPIRES_IN || '30d');
  return { access, refresh };
}

// ── POST /register ─────────────────────────────────────────────────────────────
router.post('/register', rules.register, validate, async (req, res, next) => {
  try {
    const { email, password, firstName, lastName, tenantId } = req.body;

    const existing = await findUserByEmail(email, tenantId);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const verifyToken = crypto.randomBytes(32).toString('hex');

    const { rows } = await query(
      `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, status, email_verified)
       VALUES ($1,$2,$3,$4,$5,$6,'active',FALSE) RETURNING *`,
      [uuid(), tenantId || null, email, hash, firstName, lastName]
    );
    const user = rows[0];

    // Email verification token
    await query(
      `INSERT INTO email_verifications (id, user_id, token, expires_at)
       VALUES ($1,$2,$3, NOW() + INTERVAL '24 hours')`,
      [uuid(), user.id, verifyToken]
    );

    // Send verification email (non-blocking)
    sendEmail({
      to: email,
      subject: 'Verify your AcadLMS account',
      template: 'verify',
      data: { name: firstName, token: verifyToken, url: `${process.env.FRONTEND_URL}/verify-email?token=${verifyToken}` },
    }).catch(logger.error);

    await auditLog({ userId: user.id, action: 'user.register', ip: req.ip, tenantId });

    const { access, refresh } = issueTokenPair(user.id, user.tenant_id);
    res.status(201).json({ user: await getUserPublic(user), access, refresh });
  } catch (err) { next(err); }
});

// ── POST /login ────────────────────────────────────────────────────────────────
router.post('/login', rules.login, validate, async (req, res, next) => {
  try {
    const { email, password, tenantId } = req.body;
    const user = await findUserByEmail(email, tenantId);

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.status === 'suspended') return res.status(403).json({ error: 'Account suspended' });

    // Brute-force check
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({ error: 'Account locked — too many failed attempts', until: user.locked_until });
    }

    const valid = await bcrypt.compare(password, user.password_hash || '');
    if (!valid) {
      const failedLogins = (user.failed_logins || 0) + 1;
      const lock = failedLogins >= 5 ? new Date(Date.now() + 15 * 60_000) : null;
      await query(
        `UPDATE users SET failed_logins=$1, locked_until=$2 WHERE id=$3`,
        [failedLogins, lock, user.id]
      );
      await auditLog({ userId: user.id, action: 'auth.login.failed', ip: req.ip, tenantId });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset failed logins
    await query(
      `UPDATE users SET failed_logins=0, locked_until=NULL, last_login_at=NOW(), last_login_ip=$1 WHERE id=$2`,
      [req.ip, user.id]
    );

    if (user.two_fa_enabled) {
      // Issue a short-lived pre-auth token for 2FA step
      const preAuth = signJWT({ sub: user.id, step: '2fa' }, process.env.JWT_SECRET, '5m');
      return res.json({ requiresTwoFactor: true, preAuthToken: preAuth });
    }

    const { access, refresh } = issueTokenPair(user.id, user.tenant_id);
    await query(
      `INSERT INTO sessions (id, user_id, token_hash, refresh_token, ip_address, user_agent, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6, NOW() + INTERVAL '30 days')`,
      [uuid(), user.id, hashToken(access), refresh, req.ip, req.get('user-agent')]
    );

    await auditLog({ userId: user.id, action: 'auth.login', ip: req.ip, tenantId });
    res.json({ user: await getUserPublic(user), access, refresh });
  } catch (err) { next(err); }
});

// ── POST /2fa/verify ───────────────────────────────────────────────────────────
router.post('/2fa/verify', async (req, res, next) => {
  try {
    const { preAuthToken, code } = req.body;
    let payload;
    try {
      payload = jwt.verify(preAuthToken, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ error: 'Invalid or expired pre-auth token' });
    }
    if (payload.step !== '2fa') return res.status(400).json({ error: 'Invalid token type' });

    const user = await findUserById(payload.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = speakeasy.totp.verify({
      secret: user.two_fa_secret,
      encoding: 'base32',
      token: String(code),
      window: 1,
    });
    if (!valid) return res.status(401).json({ error: 'Invalid 2FA code' });

    const { access, refresh } = issueTokenPair(user.id, user.tenant_id);
    await query(
      `INSERT INTO sessions (id, user_id, token_hash, refresh_token, ip_address, user_agent, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6, NOW() + INTERVAL '30 days')`,
      [uuid(), user.id, hashToken(access), refresh, req.ip, req.get('user-agent')]
    );

    await auditLog({ userId: user.id, action: 'auth.2fa.verified', ip: req.ip });
    res.json({ user: await getUserPublic(user), access, refresh });
  } catch (err) { next(err); }
});

// ── POST /2fa/setup ────────────────────────────────────────────────────────────
router.post('/2fa/setup', auth, async (req, res, next) => {
  try {
    const secret = speakeasy.generateSecret({
      name: `${process.env.TOTP_APP_NAME || 'AcadLMS'} (${req.user.email})`,
      length: 32,
    });
    await query(`UPDATE users SET two_fa_secret=$1 WHERE id=$2`, [secret.base32, req.user.id]);
    const qr = await qrcode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qrCode: qr });
  } catch (err) { next(err); }
});

// ── POST /2fa/enable ───────────────────────────────────────────────────────────
router.post('/2fa/enable', auth, async (req, res, next) => {
  try {
    const { code } = req.body;
    const user = await findUserById(req.user.id);
    const valid = speakeasy.totp.verify({ secret: user.two_fa_secret, encoding: 'base32', token: String(code), window: 1 });
    if (!valid) return res.status(400).json({ error: 'Invalid TOTP code' });
    await query(`UPDATE users SET two_fa_enabled=TRUE WHERE id=$1`, [user.id]);
    await auditLog({ userId: user.id, action: 'auth.2fa.enabled', ip: req.ip });
    res.json({ message: '2FA enabled successfully' });
  } catch (err) { next(err); }
});

// ── POST /2fa/disable ──────────────────────────────────────────────────────────
router.post('/2fa/disable', auth, async (req, res, next) => {
  try {
    await query(`UPDATE users SET two_fa_enabled=FALSE, two_fa_secret=NULL WHERE id=$1`, [req.user.id]);
    await auditLog({ userId: req.user.id, action: 'auth.2fa.disabled', ip: req.ip });
    res.json({ message: '2FA disabled' });
  } catch (err) { next(err); }
});

// ── POST /refresh ──────────────────────────────────────────────────────────────
router.post('/refresh', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
    const { rows } = await query(
      `SELECT * FROM sessions WHERE refresh_token=$1 AND user_id=$2 AND expires_at > NOW()`,
      [refreshToken, payload.sub]
    );
    if (!rows.length) return res.status(401).json({ error: 'Session not found or expired' });

    const user = await findUserById(payload.sub);
    const { access, refresh: newRefresh } = issueTokenPair(user.id, user.tenant_id);
    await query(
      `UPDATE sessions SET token_hash=$1, refresh_token=$2, expires_at=NOW()+INTERVAL '30 days' WHERE id=$3`,
      [hashToken(access), newRefresh, rows[0].id]
    );
    res.json({ access, refresh: newRefresh });
  } catch (err) { next(err); }
});

// ── POST /logout ───────────────────────────────────────────────────────────────
router.post('/logout', auth, async (req, res, next) => {
  try {
    await query(`DELETE FROM sessions WHERE user_id=$1 AND token_hash=$2`, [req.user.id, req.tokenHash]);
    await auditLog({ userId: req.user.id, action: 'auth.logout', ip: req.ip });
    res.json({ message: 'Logged out' });
  } catch (err) { next(err); }
});

// ── POST /logout-all ───────────────────────────────────────────────────────────
router.post('/logout-all', auth, async (req, res, next) => {
  try {
    await query(`DELETE FROM sessions WHERE user_id=$1`, [req.user.id]);
    await auditLog({ userId: req.user.id, action: 'auth.logout.all', ip: req.ip });
    res.json({ message: 'All sessions revoked' });
  } catch (err) { next(err); }
});

// ── POST /forgot-password ──────────────────────────────────────────────────────
router.post('/forgot-password', async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await findUserByEmail(email);
    if (!user) return res.json({ message: 'If that email exists, a reset link was sent.' });

    const token = crypto.randomBytes(32).toString('hex');
    await query(
      `INSERT INTO password_resets (id, user_id, token, expires_at) VALUES ($1,$2,$3, NOW()+INTERVAL '1 hour')
       ON CONFLICT DO NOTHING`,
      [uuid(), user.id, token]
    );
    sendEmail({
      to: email,
      subject: 'Reset your AcadLMS password',
      template: 'reset',
      data: { name: user.first_name, url: `${process.env.FRONTEND_URL}/reset-password?token=${token}` },
    }).catch(logger.error);
    res.json({ message: 'If that email exists, a reset link was sent.' });
  } catch (err) { next(err); }
});

// ── POST /reset-password ───────────────────────────────────────────────────────
router.post('/reset-password', async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;
    const { rows } = await query(
      `SELECT * FROM password_resets WHERE token=$1 AND expires_at > NOW()`, [token]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired reset token' });

    const hash = await bcrypt.hash(newPassword, 12);
    await query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, rows[0].user_id]);
    await query(`DELETE FROM password_resets WHERE id=$1`, [rows[0].id]);
    await query(`DELETE FROM sessions WHERE user_id=$1`, [rows[0].user_id]);
    await auditLog({ userId: rows[0].user_id, action: 'auth.password.reset', ip: req.ip });
    res.json({ message: 'Password reset successfully' });
  } catch (err) { next(err); }
});

// ── GET /verify-email ──────────────────────────────────────────────────────────
router.get('/verify-email', async (req, res, next) => {
  try {
    const { token } = req.query;
    const { rows } = await query(
      `SELECT * FROM email_verifications WHERE token=$1 AND expires_at > NOW()`, [token]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired token' });
    await query(`UPDATE users SET email_verified=TRUE WHERE id=$1`, [rows[0].user_id]);
    await query(`DELETE FROM email_verifications WHERE id=$1`, [rows[0].id]);
    res.json({ message: 'Email verified successfully' });
  } catch (err) { next(err); }
});

// ── GET /me ────────────────────────────────────────────────────────────────────
router.get('/me', auth, async (req, res, next) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(await getUserPublic(user));
  } catch (err) { next(err); }
});

// ── GET /sessions ──────────────────────────────────────────────────────────────
router.get('/sessions', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, ip_address, user_agent, created_at, expires_at FROM sessions
       WHERE user_id=$1 AND expires_at > NOW() ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// ── DELETE /sessions/:id ───────────────────────────────────────────────────────
router.delete('/sessions/:id', auth, async (req, res, next) => {
  try {
    await query(`DELETE FROM sessions WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    res.json({ message: 'Session revoked' });
  } catch (err) { next(err); }
});

module.exports = router;
