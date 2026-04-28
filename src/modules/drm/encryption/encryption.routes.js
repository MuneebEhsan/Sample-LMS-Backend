'use strict';
const router = require('express').Router();
const crypto = require('crypto');
const path   = require('path');
const fs     = require('fs');
const multer = require('multer');
const { v4: uuid }  = require('uuid');
const { query }     = require('../../../db');
const { auth, requireRole } = require('../../../common/middleware/auth');
const { auditLog }  = require('../../../common/utils/audit');
const { enqueueEncrypt } = require('../../../jobs');
const logger = require('../../../common/utils/logger');

const UPLOAD_DIR = process.env.SCORM_UPLOAD_DIR || './uploads';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (_, file, cb) => cb(null, `${uuid()}_${file.originalname}`),
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2GB max
});

// ── Encryption helpers ────────────────────────────────────────────────────────
function generateKey() {
  return crypto.randomBytes(32); // 256-bit
}

function encryptBuffer(buffer, key) {
  const iv         = crypto.randomBytes(16);
  const cipher     = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted  = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag    = cipher.getAuthTag();
  return { encrypted, iv, authTag };
}

function decryptBuffer(encrypted, key, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// Export service function for queue usage
async function encryptFile({ fileId, filePath, algorithm = 'AES-256-GCM', keyId }) {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    const keyRef     = keyId || `key_${uuid()}`;
    const masterKey  = Buffer.from(process.env.DRM_MASTER_KEY || crypto.randomBytes(32).toString('hex'), 'hex');

    // Derive file-specific key using HKDF-like approach
    const fileKey   = crypto.createHmac('sha256', masterKey).update(keyRef).digest();
    const { encrypted, iv, authTag } = encryptBuffer(fileBuffer, fileKey);

    const encryptedPath = filePath + '.enc';
    // Write: [16-byte IV][16-byte authTag][encrypted data]
    fs.writeFileSync(encryptedPath, Buffer.concat([iv, authTag, encrypted]));

    // Store key reference in DB (actual key material stored in KMS/env)
    await query(
      `INSERT INTO encryption_keys (id, key_ref, algorithm, active) VALUES ($1,$2,$3,TRUE) ON CONFLICT (key_ref) DO NOTHING`,
      [uuid(), keyRef, algorithm]
    );

    // Update protected_files record
    await query(
      `UPDATE protected_files SET encrypted_path=$1, encryption_key_id=$2, status='protected', updated_at=NOW() WHERE id=$3`,
      [encryptedPath, keyRef, fileId]
    );

    logger.info(`[DRM] File ${fileId} encrypted → ${encryptedPath}`);
    return { encryptedPath, keyRef };
  } catch (err) {
    await query(`UPDATE protected_files SET status='error' WHERE id=$1`, [fileId]);
    logger.error(`[DRM] Encrypt failed for ${fileId}:`, err.message);
    throw err;
  }
}

// ── Routes ────────────────────────────────────────────────────────────────────

/* ─── POST /drm/encrypt/upload — upload and protect a file ─────────────── */
router.post('/upload', auth, requireRole('Super Admin','Admin'), upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const {
      licenseProfileId, courseId, activityId,
      storageProvider = 'local', algorithm = 'AES-256-GCM',
    } = req.body;

    // Insert protected_files record (status=pending)
    const fileId = uuid();
    const { rows } = await query(
      `INSERT INTO protected_files (
         id, tenant_id, course_id, activity_id, original_name, mime_type,
         file_size_bytes, storage_provider, storage_path, license_profile_id,
         encryption_alg, status
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending') RETURNING *`,
      [fileId, req.user.tenantId, courseId, activityId,
       req.file.originalname, req.file.mimetype, req.file.size,
       storageProvider, req.file.path, licenseProfileId, algorithm]
    );

    // Queue encryption
    await enqueueEncrypt({ fileId, filePath: req.file.path, algorithm, keyId: `key_${fileId}` });

    await auditLog({ userId: req.user.id, action: 'drm.file.upload', resourceId: fileId, ip: req.ip });
    res.status(202).json({ file: rows[0], message: 'File queued for encryption' });
  } catch (err) { next(err); }
});

/* ─── GET /drm/encrypt/files — list protected files ────────────────────── */
router.get('/files', auth, async (req, res, next) => {
  try {
    const { courseId, status } = req.query;
    let conds = ['pf.tenant_id=$1'], params = [req.user.tenantId], p = 2;
    if (courseId) { conds.push(`pf.course_id=$${p++}`); params.push(courseId); }
    if (status)   { conds.push(`pf.status=$${p++}`);    params.push(status); }

    const { rows } = await query(
      `SELECT pf.*,
              lp.name AS license_profile_name, lp.tier, lp.encryption_alg
       FROM protected_files pf
       LEFT JOIN license_profiles lp ON lp.id=pf.license_profile_id
       WHERE ${conds.join(' AND ')}
       ORDER BY pf.created_at DESC`,
      params
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ─── GET /drm/encrypt/files/:id ────────────────────────────────────────── */
router.get('/files/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT pf.*, lp.name AS profile_name, lp.max_devices, lp.downloads_allowed,
              lp.watermark_enabled, lp.geo_enabled, lp.geo_countries
       FROM protected_files pf
       LEFT JOIN license_profiles lp ON lp.id=pf.license_profile_id
       WHERE pf.id=$1`, [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'File not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

/* ─── PATCH /drm/encrypt/files/:id — update license profile ────────────── */
router.patch('/files/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { licenseProfileId } = req.body;
    await query(
      'UPDATE protected_files SET license_profile_id=$1, updated_at=NOW() WHERE id=$2',
      [licenseProfileId, req.params.id]
    );
    await auditLog({ userId: req.user.id, action: 'drm.file.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'File updated' });
  } catch (err) { next(err); }
});

/* ─── DELETE /drm/encrypt/files/:id ────────────────────────────────────── */
router.delete('/files/:id', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM protected_files WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    // Remove local encrypted file if exists
    if (rows[0].encrypted_path && fs.existsSync(rows[0].encrypted_path)) {
      fs.unlinkSync(rows[0].encrypted_path);
    }
    await query('DELETE FROM protected_files WHERE id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'drm.file.delete', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'File deleted' });
  } catch (err) { next(err); }
});

/* ─── GET /drm/encrypt/keys — encryption key inventory ─────────────────── */
router.get('/keys', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT id, key_ref, algorithm, rotated_at, active, created_at FROM encryption_keys ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ─── POST /drm/encrypt/keys/rotate — rotate a key ─────────────────────── */
router.post('/keys/rotate', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    const { keyRef } = req.body;
    await query(
      'UPDATE encryption_keys SET rotated_at=NOW(), active=FALSE WHERE key_ref=$1', [keyRef]
    );
    const newRef = `${keyRef}_rotated_${Date.now()}`;
    const { rows } = await query(
      'INSERT INTO encryption_keys (id, key_ref, algorithm) VALUES ($1,$2,$3) RETURNING *',
      [uuid(), newRef, 'AES-256-GCM']
    );
    await auditLog({ userId: req.user.id, action: 'drm.key.rotate', detail: { oldKey: keyRef, newKey: newRef }, ip: req.ip });
    res.json({ message: 'Key rotated', newKey: rows[0] });
  } catch (err) { next(err); }
});

/* ─── GET /drm/encrypt/storage-providers ────────────────────────────────── */
router.get('/storage-providers', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, name, type, is_default, active, created_at FROM storage_providers WHERE tenant_id=$1`,
      [req.user.tenantId]
    );
    // Mask credentials
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/storage-providers', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    const { name, type, config, isDefault = false } = req.body;
    if (isDefault) {
      await query('UPDATE storage_providers SET is_default=FALSE WHERE tenant_id=$1', [req.user.tenantId]);
    }
    const { rows } = await query(
      'INSERT INTO storage_providers (id, tenant_id, name, type, config, is_default) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, type, is_default',
      [uuid(), req.user.tenantId, name, type, JSON.stringify(config), isDefault]
    );
    await auditLog({ userId: req.user.id, action: 'drm.storage.create', resourceId: rows[0].id, ip: req.ip });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
module.exports.encryptFile = encryptFile;
