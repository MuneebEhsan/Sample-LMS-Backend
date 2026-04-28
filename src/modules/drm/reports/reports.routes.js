'use strict';
const router = require('express').Router();
const { v4: uuid } = require('uuid');
const { query }    = require('../../../db');
const { auth, requireRole } = require('../../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../../common/utils/pagination');
const { enqueueReport } = require('../../../jobs');

/* ════════════════════ ACCESS REPORT ════════════════════════════════════════ */
router.get('/access', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { userId, fileId, from, to } = req.query;

    let conds = ['pf.tenant_id=$1'], params = [req.user.tenantId], p = 2;
    if (userId) { conds.push(`dt.user_id=$${p++}`); params.push(userId); }
    if (fileId) { conds.push(`dt.file_id=$${p++}`); params.push(fileId); }
    if (from)   { conds.push(`dt.created_at>=$${p++}`); params.push(from); }
    if (to)     { conds.push(`dt.created_at<=$${p++}`); params.push(to); }

    const WHERE = conds.join(' AND ');
    const { rows } = await query(
      `SELECT dt.id, dt.created_at, dt.ip_address, dt.user_agent, dt.device_id, dt.expires_at,
              u.email AS user_email, u.first_name || ' ' || u.last_name AS user_name,
              pf.original_name AS file_name, pf.mime_type
       FROM drm_tokens dt
       JOIN protected_files pf ON pf.id=dt.file_id
       JOIN users u ON u.id=dt.user_id
       WHERE ${WHERE}
       ORDER BY dt.created_at DESC LIMIT $${p++} OFFSET $${p++}`,
      [...params, limit, offset]
    );
    const cnt = await query(
      `SELECT COUNT(*) FROM drm_tokens dt JOIN protected_files pf ON pf.id=dt.file_id WHERE ${WHERE}`,
      params
    );
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

/* ════════════════════ LICENSE USAGE REPORT ══════════════════════════════════ */
router.get('/license-usage', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT lp.id, lp.name, lp.tier, lp.color,
              COUNT(DISTINCT pf.id) AS file_count,
              COUNT(DISTINCT dgp.group_id) AS group_count,
              SUM(pf.access_count) AS total_access,
              MAX(pf.last_accessed_at) AS last_access
       FROM license_profiles lp
       LEFT JOIN protected_files pf ON pf.license_profile_id=lp.id
       LEFT JOIN drm_group_profiles dgp ON dgp.license_profile_id=lp.id
       WHERE lp.tenant_id=$1
       GROUP BY lp.id ORDER BY total_access DESC NULLS LAST`,
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ════════════════════ FILE POPULARITY REPORT ═══════════════════════════════ */
router.get('/file-popularity', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT pf.id, pf.original_name, pf.mime_type,
              pf.access_count, pf.last_accessed_at, pf.created_at,
              lp.name AS profile_name
       FROM protected_files pf
       LEFT JOIN license_profiles lp ON lp.id=pf.license_profile_id
       WHERE pf.tenant_id=$1
       ORDER BY pf.access_count DESC LIMIT 20`,
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ════════════════════ VIOLATION SUMMARY ════════════════════════════════════ */
router.get('/violation-summary', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { from, to } = req.query;
    const fromDate = from || new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
    const toDate   = to   || new Date().toISOString().split('T')[0];

    const [byType, bySeverity, topOffenders, timeline] = await Promise.all([
      query(
        `SELECT violation_type, COUNT(*) AS count FROM drm_violations
         WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3 GROUP BY violation_type`,
        [req.user.tenantId, fromDate, toDate]
      ),
      query(
        `SELECT severity, COUNT(*) AS count FROM drm_violations
         WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3 GROUP BY severity`,
        [req.user.tenantId, fromDate, toDate]
      ),
      query(
        `SELECT u.email, COUNT(*) AS violations
         FROM drm_violations v JOIN users u ON u.id=v.user_id
         WHERE v.tenant_id=$1 AND v.created_at BETWEEN $2 AND $3
         GROUP BY u.id ORDER BY violations DESC LIMIT 10`,
        [req.user.tenantId, fromDate, toDate]
      ),
      query(
        `SELECT DATE_TRUNC('day', created_at) AS day, COUNT(*) AS count
         FROM drm_violations WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
         GROUP BY day ORDER BY day`,
        [req.user.tenantId, fromDate, toDate]
      ),
    ]);

    res.json({
      byType:      byType.rows,
      bySeverity:  bySeverity.rows,
      topOffenders:topOffenders.rows,
      timeline:    timeline.rows,
    });
  } catch (err) { next(err); }
});

/* ════════════════════ PERFORMANCE METRICS ═══════════════════════════════════ */
router.get('/performance', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { metric, from, to, groupBy = 'hour' } = req.query;
    const trunc = groupBy === 'day' ? 'day' : 'hour';

    const params = [];
    let conds = ['1=1'], p = 1;
    if (metric) { conds.push(`metric_name=$${p++}`); params.push(metric); }
    if (from)   { conds.push(`recorded_at>=$${p++}`); params.push(from); }
    if (to)     { conds.push(`recorded_at<=$${p++}`); params.push(to); }

    const { rows } = await query(
      `SELECT metric_name,
              DATE_TRUNC($${p++}, recorded_at) AS period,
              AVG(value) AS avg, MIN(value) AS min, MAX(value) AS max,
              COUNT(*) AS samples
       FROM performance_metrics
       WHERE ${conds.join(' AND ')}
       GROUP BY metric_name, period ORDER BY period DESC LIMIT 1000`,
      [...params, trunc]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ─── Record a performance metric (called by monitoring agents) ────────── */
router.post('/performance', auth, async (req, res, next) => {
  try {
    const { metricName, value, unit, tags = {} } = req.body;
    await query(
      'INSERT INTO performance_metrics (id, metric_name, value, unit, tags) VALUES ($1,$2,$3,$4,$5)',
      [uuid(), metricName, value, unit, JSON.stringify(tags)]
    );
    res.status(201).json({ message: 'Metric recorded' });
  } catch (err) { next(err); }
});

/* ─── System health snapshot ────────────────────────────────────────────── */
router.get('/system-health', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const os = require('os');
    const dbStart = Date.now();
    await query('SELECT 1');
    const dbLatency = Date.now() - dbStart;

    const totalMem = os.totalmem();
    const freeMem  = os.freemem();

    res.json({
      uptime:      process.uptime(),
      dbLatencyMs: dbLatency,
      memoryUsage: {
        total:    totalMem,
        free:     freeMem,
        used:     totalMem - freeMem,
        usedPct:  Math.round((totalMem - freeMem) / totalMem * 100),
      },
      cpu:    os.cpus().length,
      loadAvg:os.loadavg(),
      nodeVersion: process.version,
      timestamp: new Date().toISOString(),
    });
  } catch (err) { next(err); }
});

/* ════════════════════ SCHEDULED REPORTS ════════════════════════════════════ */
router.get('/scheduled', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT * FROM scheduled_reports WHERE tenant_id=$1 ORDER BY created_at DESC',
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/scheduled', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, template, format = 'PDF', frequency = 'weekly', recipients = [] } = req.body;
    const { rows } = await query(
      `INSERT INTO scheduled_reports (id, tenant_id, name, template, format, frequency, recipients)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [uuid(), req.user.tenantId, name, template, format, frequency, recipients]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.delete('/scheduled/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    await query('DELETE FROM scheduled_reports WHERE id=$1', [req.params.id]);
    res.json({ message: 'Report schedule deleted' });
  } catch (err) { next(err); }
});

/* ─── Trigger a scheduled report manually ──────────────────────────────── */
router.post('/scheduled/:id/run', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM scheduled_reports WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    await enqueueReport({ ...rows[0], tenantId: req.user.tenantId });
    await query('UPDATE scheduled_reports SET last_run_at=NOW() WHERE id=$1', [req.params.id]);
    res.json({ message: 'Report queued' });
  } catch (err) { next(err); }
});

/* ─── Service for job queue ─────────────────────────────────────────────── */
async function generateScheduledReport({ id, template, format, recipients, tenantId }) {
  // Stub: generate PDF/CSV and email to recipients
  const logger = require('../../../common/utils/logger');
  logger.info(`[report] Generating ${template} (${format}) for tenant ${tenantId}`);
}

module.exports = router;
module.exports.generateScheduledReport = generateScheduledReport;
