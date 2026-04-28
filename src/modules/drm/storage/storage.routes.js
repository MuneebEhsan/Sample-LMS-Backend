'use strict';
const router = require('express').Router();
const { v4: uuid } = require('uuid');
const { query }    = require('../../db');
const { auth, requireRole } = require('../../../common/middleware/auth');
const { auditLog } = require('../../../common/utils/audit');
const logger = require('../../../common/utils/logger');

/* ════════════════════ FILE RIGHTS MANAGEMENT ════════════════════════════════ */
/**
 * Assign a license profile to a file, folder, user, or group.
 * POST /drm/storage/rights
 */
router.post('/rights', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { fileIds = [], subjectType, subjectId, licenseProfileId, expiresAt } = req.body;
    for (const fileId of fileIds) {
      await query(
        `INSERT INTO file_rights (id, file_id, subject_type, subject_id, license_profile_id, expires_at, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT DO NOTHING`,
        [uuid(), fileId, subjectType, subjectId, licenseProfileId, expiresAt, req.user.id]
      );
    }
    await auditLog({
      userId: req.user.id, action: 'drm.rights.assign',
      detail: { fileIds, subjectType, subjectId, licenseProfileId }, ip: req.ip,
    });
    res.status(201).json({ message: `Rights assigned to ${fileIds.length} file(s)` });
  } catch (err) { next(err); }
});

router.get('/rights', auth, async (req, res, next) => {
  try {
    const { fileId, subjectType, subjectId } = req.query;
    let conds = ['1=1'], params = [], p = 1;
    if (fileId)     { conds.push(`fr.file_id=$${p++}`);      params.push(fileId); }
    if (subjectType){ conds.push(`fr.subject_type=$${p++}`); params.push(subjectType); }
    if (subjectId)  { conds.push(`fr.subject_id::text=$${p++}`); params.push(subjectId); }

    const { rows } = await query(
      `SELECT fr.*,
              pf.original_name AS file_name,
              lp.name AS profile_name
       FROM file_rights fr
       JOIN protected_files pf ON pf.id=fr.file_id
       LEFT JOIN license_profiles lp ON lp.id=fr.license_profile_id
       WHERE ${conds.join(' AND ')}
       ORDER BY fr.created_at DESC`,
      params
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.delete('/rights/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    await query('DELETE FROM file_rights WHERE id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'drm.rights.revoke', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Rights revoked' });
  } catch (err) { next(err); }
});

/* ════════════════════ CLOUD STORAGE BROWSER ════════════════════════════════ */
router.get('/browse', auth, async (req, res, next) => {
  try {
    const { provider, prefix = '' } = req.query;
    const { rows } = await query(
      'SELECT * FROM storage_providers WHERE tenant_id=$1 AND active=TRUE',
      [req.user.tenantId]
    );
    if (!rows.length) return res.json({ files: [], providers: [] });

    // Return protected files as a virtual file browser
    const { rows: files } = await query(
      `SELECT pf.id, pf.original_name AS name, pf.mime_type, pf.file_size_bytes,
              pf.storage_path, pf.status, pf.access_count, pf.created_at,
              lp.name AS license_profile
       FROM protected_files pf
       LEFT JOIN license_profiles lp ON lp.id=pf.license_profile_id
       WHERE pf.tenant_id=$1
         AND ($2 = '' OR pf.original_name ILIKE $2)
       ORDER BY pf.created_at DESC`,
      [req.user.tenantId, prefix ? `%${prefix}%` : '']
    );

    res.json({ files, providers: rows.map(r => ({ id: r.id, name: r.name, type: r.type, isDefault: r.is_default })) });
  } catch (err) { next(err); }
});

/* ─── Signed URL generation ─────────────────────────────────────────────── */
router.post('/signed-url', auth, async (req, res, next) => {
  try {
    const { fileId, ttl = 900 } = req.body;
    const { rows } = await query(
      'SELECT * FROM protected_files WHERE id=$1 AND tenant_id=$2',
      [fileId, req.user.tenantId]
    );
    if (!rows.length) return res.status(404).json({ error: 'File not found' });

    const jwt   = require('jsonwebtoken');
    const token = jwt.sign(
      { fid: fileId, uid: req.user.id, type: 'signed' },
      process.env.DRM_TOKEN_SECRET || process.env.JWT_SECRET,
      { expiresIn: ttl }
    );

    const signedUrl = `${process.env.API_BASE_URL || 'http://localhost:4000'}/api/v1/drm/tokens/stream/${fileId}?token=${token}`;
    res.json({ signedUrl, expiresIn: ttl, expiresAt: new Date(Date.now() + ttl * 1000) });
  } catch (err) { next(err); }
});

/* ─── Watermark templates ────────────────────────────────────────────────── */
router.get('/watermarks', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT * FROM watermark_templates WHERE tenant_id=$1 ORDER BY name',
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/watermarks', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, template, position = 'diagonal', opacity = 0.3, fontSize = 14, color } = req.body;
    const { rows } = await query(
      `INSERT INTO watermark_templates (id, tenant_id, name, template, position, opacity, font_size, color)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [uuid(), req.user.tenantId, name, template, position, opacity, fontSize, color]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/watermarks/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, template, position, opacity, fontSize, color } = req.body;
    await query(
      `UPDATE watermark_templates SET
         name=COALESCE($1,name), template=COALESCE($2,template),
         position=COALESCE($3,position), opacity=COALESCE($4,opacity),
         font_size=COALESCE($5,font_size), color=COALESCE($6,color)
       WHERE id=$7`,
      [name, template, position, opacity, fontSize, color, req.params.id]
    );
    res.json({ message: 'Watermark template updated' });
  } catch (err) { next(err); }
});

module.exports = router;
