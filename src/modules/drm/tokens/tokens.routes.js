'use strict';
const router = require('express').Router();
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuid }  = require('uuid');
const { query }     = require('../../db');
const { auth, drmAuth, requireRole } = require('../../../common/middleware/auth');
const { auditLog }  = require('../../../common/utils/audit');
const { emitDRMEvent } = require('../../../websocket');
const logger = require('../../../common/utils/logger');

const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

/* ════════════════════ TOKEN ISSUANCE ════════════════════════════════════════ */
/**
 * POST /drm/tokens/issue
 * Body: { fileId, deviceId? }
 * Returns: { token, expiresAt, streamUrl }
 */
router.post('/issue', auth, async (req, res, next) => {
  try {
    const { fileId, deviceId } = req.body;
    const userId    = req.user.id;

    // 1. Fetch file + license profile
    const { rows: fileRows } = await query(
      `SELECT pf.*, lp.* FROM protected_files pf
       LEFT JOIN license_profiles lp ON lp.id=pf.license_profile_id
       WHERE pf.id=$1 AND pf.status='protected'`, [fileId]
    );
    if (!fileRows.length) return res.status(404).json({ error: 'Protected file not found' });
    const file = fileRows[0];

    // 2. Check user has rights
    const hasRights = await checkUserRights(userId, fileId, file.license_profile_id);
    if (!hasRights) {
      await recordViolation({ userId, fileId, type: 'no_license', ip: req.ip, ua: req.get('user-agent'), tenantId: req.user.tenantId });
      return res.status(403).json({ error: 'No valid license for this file' });
    }

    // 3. Geo-check
    if (file.geo_enabled) {
      const allowed = await checkGeo(req.ip, file.geo_countries || []);
      if (!allowed) {
        await recordViolation({ userId, fileId, type: 'geo_block', ip: req.ip, ua: req.get('user-agent'), tenantId: req.user.tenantId });
        return res.status(403).json({ error: 'Access blocked in your region' });
      }
    }

    // 4. Device limit check
    if (file.max_devices) {
      const { rows: devices } = await query(
        'SELECT device_id FROM user_devices WHERE user_id=$1', [userId]
      );
      const deviceIds = devices.map(d => d.device_id);
      if (deviceId && !deviceIds.includes(deviceId) && deviceIds.length >= file.max_devices) {
        await recordViolation({ userId, fileId, type: 'device_limit', ip: req.ip, ua: req.get('user-agent'), tenantId: req.user.tenantId });
        return res.status(403).json({ error: 'Device limit exceeded' });
      }
      // Register device
      if (deviceId) {
        await query(
          `INSERT INTO user_devices (id, user_id, device_id, device_name, last_seen)
           VALUES ($1,$2,$3,$4,NOW())
           ON CONFLICT (user_id, device_id) DO UPDATE SET last_seen=NOW()`,
          [uuid(), userId, deviceId, req.get('user-agent')?.split('/')[0] || 'Browser']
        );
      }
    }

    // 5. Max concurrent streams check
    if (file.max_streams) {
      const { rows: activeTokens } = await query(
        `SELECT COUNT(*) FROM drm_tokens WHERE user_id=$1 AND file_id=$2 AND expires_at > NOW() AND revoked=FALSE`,
        [userId, fileId]
      );
      if (parseInt(activeTokens[0].count) >= file.max_streams) {
        return res.status(429).json({ error: 'Max concurrent streams reached' });
      }
    }

    // 6. Issue token
    const ttl       = file.token_ttl_seconds || 3600;
    const expiresAt = new Date(Date.now() + ttl * 1000);
    const rawToken  = jwt.sign(
      { sub: userId, fid: fileId, tid: req.user.tenantId, type: 'drm' },
      process.env.DRM_TOKEN_SECRET || process.env.JWT_SECRET,
      { expiresIn: ttl }
    );
    const tokenHash = hashToken(rawToken);

    await query(
      `INSERT INTO drm_tokens (id, file_id, user_id, token_hash, ip_address, user_agent, device_id, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [uuid(), fileId, userId, tokenHash, req.ip, req.get('user-agent'), deviceId, expiresAt]
    );

    // Update access count
    await query(
      'UPDATE protected_files SET access_count=access_count+1, last_accessed_at=NOW() WHERE id=$1', [fileId]
    );

    // Emit live DRM event
    try { emitDRMEvent(req.user.tenantId, { type: 'access', userId, fileId, ip: req.ip }); } catch {}

    await auditLog({ userId, action: 'drm.token.issued', resourceId: fileId, detail: { deviceId }, ip: req.ip });

    const streamUrl = `/api/v1/drm/tokens/stream/${fileId}?token=${rawToken}`;
    res.json({ token: rawToken, expiresAt, streamUrl, ttl });
  } catch (err) { next(err); }
});

/* ─── GET /drm/tokens/stream/:fileId — serve encrypted content with token ── */
router.get('/stream/:fileId', drmAuth, async (req, res, next) => {
  try {
    const { fileId } = req.params;
    const drmToken   = req.drmToken;

    if (drmToken.file_id !== fileId)
      return res.status(403).json({ error: 'Token does not match file' });

    const { rows } = await query(
      'SELECT * FROM protected_files WHERE id=$1', [fileId]
    );
    if (!rows.length) return res.status(404).json({ error: 'File not found' });

    const file = rows[0];
    const fs   = require('fs');

    if (file.storage_provider === 'local') {
      const encPath = file.encrypted_path || file.storage_path;
      if (!fs.existsSync(encPath)) return res.status(404).json({ error: 'File not on disk' });

      // Mark token as used
      await query('UPDATE drm_tokens SET used_at=NOW() WHERE id=$1', [drmToken.id]);

      // Decrypt on-the-fly for delivery
      const encData  = fs.readFileSync(encPath);
      const iv       = encData.slice(0, 16);
      const authTag  = encData.slice(16, 32);
      const payload  = encData.slice(32);

      const masterKey = Buffer.from(process.env.DRM_MASTER_KEY || '0'.repeat(64), 'hex');
      const fileKey   = require('crypto').createHmac('sha256', masterKey).update(file.encryption_key_id || 'default').digest();

      const decipher = require('crypto').createDecipheriv('aes-256-gcm', fileKey, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(payload), decipher.final()]);

      res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
      res.setHeader('Content-Length', decrypted.length);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.send(decrypted);
    } else {
      // For cloud storage, redirect to signed URL
      res.json({ signedUrl: `https://cdn.example.com/${file.storage_path}?token=${req.query.token}`, expiresIn: 900 });
    }
  } catch (err) { next(err); }
});

/* ─── POST /drm/tokens/revoke ────────────────────────────────────────────── */
router.post('/revoke', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { tokenId, userId, fileId, all } = req.body;
    if (all && userId) {
      await query('UPDATE drm_tokens SET revoked=TRUE WHERE user_id=$1', [userId]);
    } else if (fileId && userId) {
      await query('UPDATE drm_tokens SET revoked=TRUE WHERE user_id=$1 AND file_id=$2', [userId, fileId]);
    } else if (tokenId) {
      await query('UPDATE drm_tokens SET revoked=TRUE WHERE id=$1', [tokenId]);
    }
    await auditLog({ userId: req.user.id, action: 'drm.token.revoke', detail: { tokenId, userId, fileId }, ip: req.ip });
    res.json({ message: 'Token(s) revoked' });
  } catch (err) { next(err); }
});

/* ─── GET /drm/tokens/user/:userId — user's active tokens ─────────────── */
router.get('/user/:userId', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT dt.*, pf.original_name AS file_name
       FROM drm_tokens dt JOIN protected_files pf ON pf.id=dt.file_id
       WHERE dt.user_id=$1 AND dt.expires_at > NOW() AND dt.revoked=FALSE
       ORDER BY dt.created_at DESC`,
      [req.params.userId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ─── Helpers ──────────────────────────────────────────────────────────── */
async function checkUserRights(userId, fileId, licenseProfileId) {
  if (!licenseProfileId) return true; // No profile = unrestricted
  // Check file_rights for user or user's groups
  const { rows } = await query(
    `SELECT 1 FROM file_rights
     WHERE file_id=$1
       AND ((subject_type='user' AND subject_id=$2)
         OR (subject_type='group' AND subject_id IN (
             SELECT group_id FROM drm_group_members WHERE user_id=$2
           )))
       AND (expires_at IS NULL OR expires_at > NOW())
     LIMIT 1`,
    [fileId, userId]
  );
  return rows.length > 0;
}

async function checkGeo(ip, allowedCountries) {
  if (!allowedCountries.length) return true;
  // Stub: in production integrate MaxMind GeoIP2 or similar
  return true;
}

async function recordViolation({ userId, fileId, type, ip, ua, tenantId }) {
  const severity = { no_license: 'high', device_limit: 'medium', geo_block: 'medium', expired: 'low' }[type] || 'medium';
  await query(
    `INSERT INTO drm_violations (id, tenant_id, user_id, file_id, violation_type, severity, ip_address, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [uuid(), tenantId, userId, fileId, type, severity, ip, ua]
  );
}

module.exports = router;
