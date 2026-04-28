'use strict';
const router = require('express').Router();
const { v4: uuid } = require('uuid');
const { query }    = require('../../../db');
const { auth, requireRole } = require('../../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../../common/utils/pagination');
const { auditLog } = require('../../../common/utils/audit');

/* ════════════════════ LICENSE PROFILES ══════════════════════════════════════ */
/**
 * @swagger
 * /drm/licenses:
 *   get:
 *     summary: List all DRM license profiles
 *     tags: [DRM]
 */
router.get('/', auth, async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { rows } = await query(
      `SELECT lp.*,
              COUNT(DISTINCT pf.id) AS file_count
       FROM license_profiles lp
       LEFT JOIN protected_files pf ON pf.license_profile_id = lp.id
       WHERE lp.tenant_id=$1
       GROUP BY lp.id
       ORDER BY lp.created_at DESC LIMIT $2 OFFSET $3`,
      [req.user.tenantId, limit, offset]
    );
    const cnt = await query('SELECT COUNT(*) FROM license_profiles WHERE tenant_id=$1', [req.user.tenantId]);
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM license_profiles WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'License profile not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

router.post('/', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const {
      name, description, color = '#F59E0B', tier = 'standard',
      maxDevices = 3, maxStreams = 2,
      downloadsAllowed = false, offlineAllowed = false, offlineTtlHours = 24,
      watermarkEnabled = true, screenBlock = true,
      geoEnabled = false, geoCountries = [],
      windowStart = '00:00', windowEnd = '23:59',
      expiryDays, maxPlays, tokenTtlSeconds = 3600,
      encryptionAlg = 'AES-256-GCM',
    } = req.body;

    const { rows } = await query(
      `INSERT INTO license_profiles (
         id, tenant_id, name, description, color, tier,
         max_devices, max_streams, downloads_allowed, offline_allowed, offline_ttl_hours,
         watermark_enabled, screen_block, geo_enabled, geo_countries,
         window_start, window_end, expiry_days, max_plays,
         token_ttl_seconds, encryption_alg
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
       RETURNING *`,
      [uuid(), req.user.tenantId, name, description, color, tier,
       maxDevices, maxStreams, downloadsAllowed, offlineAllowed, offlineTtlHours,
       watermarkEnabled, screenBlock, geoEnabled, geoCountries,
       windowStart, windowEnd, expiryDays, maxPlays,
       tokenTtlSeconds, encryptionAlg]
    );
    await auditLog({ userId: req.user.id, action: 'drm.license.create', resourceId: rows[0].id, ip: req.ip });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const allowed = ['name','description','color','tier','max_devices','max_streams',
                     'downloads_allowed','offline_allowed','offline_ttl_hours',
                     'watermark_enabled','screen_block','geo_enabled','geo_countries',
                     'window_start','window_end','expiry_days','max_plays',
                     'token_ttl_seconds','encryption_alg'];
    const fields = [], values = [];
    let p = 1;
    for (const key of allowed) {
      const camel = key.replace(/_([a-z])/g, (_,c) => c.toUpperCase());
      if (req.body[camel] !== undefined || req.body[key] !== undefined) {
        fields.push(`${key}=$${p++}`);
        values.push(req.body[camel] ?? req.body[key]);
      }
    }
    if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
    values.push(req.params.id);
    await query(`UPDATE license_profiles SET ${fields.join(',')}, updated_at=NOW() WHERE id=$${p}`, values);
    await auditLog({ userId: req.user.id, action: 'drm.license.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'License profile updated' });
  } catch (err) { next(err); }
});

router.delete('/:id', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    // Check if in use
    const { rows } = await query('SELECT COUNT(*) FROM protected_files WHERE license_profile_id=$1', [req.params.id]);
    if (parseInt(rows[0].count) > 0)
      return res.status(409).json({ error: 'License profile is in use by protected files' });
    await query('DELETE FROM license_profiles WHERE id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'drm.license.delete', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'License profile deleted' });
  } catch (err) { next(err); }
});

/* ════════════════════ DRM USER GROUPS ═══════════════════════════════════════ */
router.get('/groups', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT dg.*,
              COUNT(DISTINCT dgm.user_id) AS member_count,
              json_agg(DISTINCT lp.name) FILTER (WHERE lp.name IS NOT NULL) AS profiles
       FROM drm_groups dg
       LEFT JOIN drm_group_members dgm ON dgm.group_id=dg.id
       LEFT JOIN drm_group_profiles dgp ON dgp.group_id=dg.id
       LEFT JOIN license_profiles lp    ON lp.id=dgp.license_profile_id
       WHERE dg.tenant_id=$1
       GROUP BY dg.id ORDER BY dg.created_at DESC`,
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/groups', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, description, color = '#6366F1', autoRule = {}, expiresAt } = req.body;
    const { rows } = await query(
      `INSERT INTO drm_groups (id, tenant_id, name, description, color, auto_rule, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [uuid(), req.user.tenantId, name, description, color, JSON.stringify(autoRule), expiresAt]
    );
    await auditLog({ userId: req.user.id, action: 'drm.group.create', resourceId: rows[0].id, ip: req.ip });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/groups/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, description, color, active, expiresAt } = req.body;
    await query(
      `UPDATE drm_groups SET
         name=COALESCE($1,name), description=COALESCE($2,description),
         color=COALESCE($3,color), active=COALESCE($4,active),
         expires_at=COALESCE($5,expires_at)
       WHERE id=$6`,
      [name, description, color, active, expiresAt, req.params.id]
    );
    res.json({ message: 'Group updated' });
  } catch (err) { next(err); }
});

router.delete('/groups/:id', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    await query('DELETE FROM drm_groups WHERE id=$1', [req.params.id]);
    res.json({ message: 'Group deleted' });
  } catch (err) { next(err); }
});

/* ─── Group members ──────────────────────────────────────────────────────── */
router.post('/groups/:id/members', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { userIds = [] } = req.body;
    for (const uid of userIds) {
      await query(
        'INSERT INTO drm_group_members (group_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [req.params.id, uid]
      );
    }
    res.json({ message: `${userIds.length} users added` });
  } catch (err) { next(err); }
});

router.delete('/groups/:id/members/:userId', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    await query('DELETE FROM drm_group_members WHERE group_id=$1 AND user_id=$2', [req.params.id, req.params.userId]);
    res.json({ message: 'Member removed' });
  } catch (err) { next(err); }
});

/* ─── Group → license profile assignments ───────────────────────────────── */
router.post('/groups/:id/profiles', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { profileIds = [] } = req.body;
    for (const pid of profileIds) {
      await query(
        'INSERT INTO drm_group_profiles (group_id, license_profile_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [req.params.id, pid]
      );
    }
    res.json({ message: 'Profiles assigned' });
  } catch (err) { next(err); }
});

/* ════════════════════ DRM DASHBOARD STATS ═══════════════════════════════════ */
router.get('/dashboard', auth, async (req, res, next) => {
  try {
    const [files, activeLicenses, violations, tokens, recentAccess] = await Promise.all([
      query('SELECT COUNT(*) FROM protected_files WHERE tenant_id=$1', [req.user.tenantId]),
      query(`SELECT COUNT(*) FROM license_profiles WHERE tenant_id=$1`, [req.user.tenantId]),
      query(`SELECT COUNT(*) FROM drm_violations WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '7d'`, [req.user.tenantId]),
      query(`SELECT COUNT(*) FROM drm_tokens dt JOIN protected_files pf ON pf.id=dt.file_id WHERE pf.tenant_id=$1 AND dt.expires_at > NOW()`, [req.user.tenantId]),
      query(
        `SELECT dt.created_at, u.email, pf.original_name AS file, dt.ip_address
         FROM drm_tokens dt
         JOIN protected_files pf ON pf.id=dt.file_id
         JOIN users u ON u.id=dt.user_id
         WHERE pf.tenant_id=$1
         ORDER BY dt.created_at DESC LIMIT 10`,
        [req.user.tenantId]
      ),
    ]);
    res.json({
      totalFiles:      parseInt(files.rows[0].count),
      activeProfiles:  parseInt(activeLicenses.rows[0].count),
      recentViolations:parseInt(violations.rows[0].count),
      activeTokens:    parseInt(tokens.rows[0].count),
      recentAccess:    recentAccess.rows,
    });
  } catch (err) { next(err); }
});

module.exports = router;
