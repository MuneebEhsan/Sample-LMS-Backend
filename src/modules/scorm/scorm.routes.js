'use strict';
const router = require('express').Router();
const multer = require('multer');
const path   = require('path');
const fs     = require('fs');
const { v4: uuid }  = require('uuid');
const { query }     = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../common/utils/pagination');
const { auditLog }  = require('../../common/utils/audit');
const { enqueueScorm } = require('../../jobs');

const SCORM_DIR = process.env.SCORM_UPLOAD_DIR || './uploads/scorm';
if (!fs.existsSync(SCORM_DIR)) fs.mkdirSync(SCORM_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: SCORM_DIR,
    filename: (_req, file, cb) => cb(null, `${uuid()}_${file.originalname}`),
  }),
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.zip', '.scorm'].includes(ext)) cb(null, true);
    else cb(new Error('Only .zip SCORM packages allowed'));
  },
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB
});

/* ════════════════════ SCORM PACKAGES ════════════════════════════════════════ */
router.get('/', auth, async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { courseId } = req.query;

    let conds = ['sp.tenant_id=$1'], params = [req.user.tenantId], p = 2;
    if (courseId) { conds.push(`sp.course_id=$${p++}`); params.push(courseId); }

    const { rows } = await query(
      `SELECT sp.*,
              c.title AS course_title
       FROM scorm_packages sp
       LEFT JOIN courses c ON c.id=sp.course_id
       WHERE ${conds.join(' AND ')}
       ORDER BY sp.created_at DESC LIMIT $${p++} OFFSET $${p++}`,
      [...params, limit, offset]
    );
    const cnt = await query(`SELECT COUNT(*) FROM scorm_packages sp WHERE ${conds.join(' AND ')}`, params);
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM scorm_packages WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'SCORM package not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

/* ─── Upload SCORM package ──────────────────────────────────────────────── */
router.post('/upload', auth, requireRole('Super Admin','Admin','Instructor'), upload.single('package'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const { title, version = '1.2', courseId } = req.body;

    const packageId = uuid();
    const { rows } = await query(
      `INSERT INTO scorm_packages (id, tenant_id, course_id, title, version, storage_path, status)
       VALUES ($1,$2,$3,$4,$5,$6,'processing') RETURNING *`,
      [packageId, req.user.tenantId, courseId, title || req.file.originalname.replace(/\.zip$/i,''), version, req.file.path]
    );

    // Queue SCORM extraction and manifest parsing
    await enqueueScorm({ packageId, filePath: req.file.path, version });
    await auditLog({ userId: req.user.id, action: 'scorm.upload', resourceId: packageId, ip: req.ip });
    res.status(202).json({ package: rows[0], message: 'Package queued for processing' });
  } catch (err) { next(err); }
});

router.delete('/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM scorm_packages WHERE id=$1', [req.params.id]);
    if (rows.length && rows[0].storage_path && fs.existsSync(rows[0].storage_path)) {
      fs.unlinkSync(rows[0].storage_path);
    }
    await query('DELETE FROM scorm_packages WHERE id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'scorm.delete', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'SCORM package deleted' });
  } catch (err) { next(err); }
});

/* ════════════════════ SCORM TRACKING (CMI data) ═════════════════════════════ */
router.get('/:packageId/tracking', auth, async (req, res, next) => {
  try {
    const uid = req.query.userId || req.user.id;
    const { rows } = await query(
      'SELECT * FROM scorm_tracking WHERE package_id=$1 AND user_id=$2',
      [req.params.packageId, uid]
    );
    res.json(rows[0] || { cmi_data: {}, completion: 'incomplete', success: 'unknown' });
  } catch (err) { next(err); }
});

/* ─── POST /scorm/:packageId/tracking — update CMI data (SCORM runtime) ── */
router.post('/:packageId/tracking', auth, async (req, res, next) => {
  try {
    const {
      cmiData = {}, scoreRaw, scoreMin, scoreMax,
      completion = 'incomplete', success = 'unknown', totalTime,
    } = req.body;

    await query(
      `INSERT INTO scorm_tracking (id, package_id, user_id, cmi_data, score_raw, score_min, score_max,
         completion, success, total_time, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
       ON CONFLICT (package_id, user_id) DO UPDATE SET
         cmi_data=$4, score_raw=$5, score_min=$6, score_max=$7,
         completion=$8, success=$9, total_time=$10, updated_at=NOW()`,
      [uuid(), req.params.packageId, req.user.id, JSON.stringify(cmiData),
       scoreRaw, scoreMin, scoreMax, completion, success, totalTime]
    );

    if (completion === 'completed') {
      await query(
        'UPDATE scorm_packages SET completions=completions+1 WHERE id=$1',
        [req.params.packageId]
      );
    }
    res.json({ message: 'Tracking data saved' });
  } catch (err) { next(err); }
});

/* ─── xAPI (TinCan) statement endpoint ─────────────────────────────────── */
router.post('/xapi/statements', auth, async (req, res, next) => {
  try {
    const statement = req.body;
    // Store in scorm_tracking.last_xapi_statement keyed by packageId if present
    const packageId = statement?.context?.extensions?.packageId;
    if (packageId) {
      await query(
        `INSERT INTO scorm_tracking (id, package_id, user_id, last_xapi_statement, updated_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (package_id, user_id) DO UPDATE SET last_xapi_statement=$4, updated_at=NOW()`,
        [uuid(), packageId, req.user.id, JSON.stringify(statement)]
      );
    }
    res.status(204).end();
  } catch (err) { next(err); }
});

/* ─── Get all tracking for a package (admin view) ─────────────────────── */
router.get('/:packageId/tracking/all', auth, requireRole('Super Admin','Admin','Instructor'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT st.*,
              u.email, u.first_name || ' ' || u.last_name AS user_name
       FROM scorm_tracking st JOIN users u ON u.id=st.user_id
       WHERE st.package_id=$1
       ORDER BY st.updated_at DESC`,
      [req.params.packageId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ════════════════════ H5P CONTENT ═══════════════════════════════════════════ */
router.get('/h5p', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT h.*, c.title AS course_title
       FROM h5p_content h LEFT JOIN courses c ON c.id=h.course_id
       WHERE h.tenant_id=$1 ORDER BY h.created_at DESC`,
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/h5p', auth, requireRole('Super Admin','Admin','Instructor'), async (req, res, next) => {
  try {
    const { title, h5pType, content = {}, library, courseId } = req.body;
    const { rows } = await query(
      `INSERT INTO h5p_content (id, tenant_id, course_id, title, h5p_type, content, library)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [uuid(), req.user.tenantId, courseId, title, h5pType, JSON.stringify(content), library]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/h5p/:id', auth, async (req, res, next) => {
  try {
    const { title, content, status } = req.body;
    await query(
      `UPDATE h5p_content SET title=COALESCE($1,title), content=COALESCE($2,content),
         status=COALESCE($3,status) WHERE id=$4`,
      [title, content ? JSON.stringify(content) : null, status, req.params.id]
    );
    res.json({ message: 'H5P content updated' });
  } catch (err) { next(err); }
});

router.delete('/h5p/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    await query('DELETE FROM h5p_content WHERE id=$1', [req.params.id]);
    res.json({ message: 'H5P content deleted' });
  } catch (err) { next(err); }
});

/* ─── SCORM service for job queue ──────────────────────────────────────── */
async function processScormPackage({ packageId, filePath, version }) {
  const logger = require('../../common/utils/logger');
  try {
    logger.info(`[SCORM] Processing package ${packageId} (v${version})`);
    // In production: extract ZIP, parse imsmanifest.xml, store assets
    // For now, mark as active with stub manifest
    const AdmZip = require('adm-zip');
    if (fs.existsSync(filePath)) {
      const zip      = new AdmZip(filePath);
      const manifest = zip.readAsText('imsmanifest.xml') || '<manifest/>';
      await query(
        `UPDATE scorm_packages SET status='active', manifest=$1 WHERE id=$2`,
        [JSON.stringify({ raw: manifest.substring(0, 1000) }), packageId]
      );
    }
  } catch (err) {
    logger.error(`[SCORM] Failed to process ${packageId}:`, err.message);
    await query("UPDATE scorm_packages SET status='error' WHERE id=$1", [packageId]);
  }
}

module.exports = router;
module.exports.processScormPackage = processScormPackage;
