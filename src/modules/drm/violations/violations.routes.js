'use strict';
const router = require('express').Router();
const { v4: uuid } = require('uuid');
const { query }    = require('../../../db');
const { auth, requireRole } = require('../../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../../common/utils/pagination');
const { auditLog } = require('../../../common/utils/audit');

/* ════════════════════ VIOLATIONS ════════════════════════════════════════════ */
router.get('/', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { userId, type, severity, resolved, from, to } = req.query;

    let conds = ['v.tenant_id=$1'], params = [req.user.tenantId], p = 2;
    if (userId)   { conds.push(`v.user_id=$${p++}`);       params.push(userId); }
    if (type)     { conds.push(`v.violation_type=$${p++}`);params.push(type); }
    if (severity) { conds.push(`v.severity=$${p++}`);      params.push(severity); }
    if (resolved !== undefined) { conds.push(`v.resolved=$${p++}`); params.push(resolved === 'true'); }
    if (from)     { conds.push(`v.created_at>=$${p++}`);   params.push(from); }
    if (to)       { conds.push(`v.created_at<=$${p++}`);   params.push(to); }

    const WHERE = conds.join(' AND ');
    const { rows } = await query(
      `SELECT v.*,
              u.email AS user_email,
              u.first_name || ' ' || u.last_name AS user_name,
              pf.original_name AS file_name
       FROM drm_violations v
       LEFT JOIN users u         ON u.id  = v.user_id
       LEFT JOIN protected_files pf ON pf.id = v.file_id
       WHERE ${WHERE}
       ORDER BY v.created_at DESC LIMIT $${p++} OFFSET $${p++}`,
      [...params, limit, offset]
    );
    const cnt = await query(`SELECT COUNT(*) FROM drm_violations v WHERE ${WHERE}`, params);
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT v.*,
              u.email AS user_email,
              pf.original_name AS file_name,
              rb.email AS resolved_by_email
       FROM drm_violations v
       LEFT JOIN users u         ON u.id  = v.user_id
       LEFT JOIN protected_files pf ON pf.id = v.file_id
       LEFT JOIN users rb        ON rb.id = v.resolved_by
       WHERE v.id=$1`, [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Violation not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:id/resolve', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { actionTaken } = req.body;
    await query(
      `UPDATE drm_violations SET resolved=TRUE, resolved_by=$1, resolved_at=NOW(), action_taken=$2 WHERE id=$3`,
      [req.user.id, actionTaken, req.params.id]
    );
    await auditLog({ userId: req.user.id, action: 'drm.violation.resolve', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Violation resolved' });
  } catch (err) { next(err); }
});

/* ─── Export violations as CSV ──────────────────────────────────────────── */
router.get('/export/csv', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT v.created_at, u.email, v.violation_type, v.severity, pf.original_name AS file,
              v.ip_address, v.action_taken, v.resolved
       FROM drm_violations v
       LEFT JOIN users u ON u.id=v.user_id
       LEFT JOIN protected_files pf ON pf.id=v.file_id
       WHERE v.tenant_id=$1 ORDER BY v.created_at DESC LIMIT 10000`,
      [req.user.tenantId]
    );
    const header = 'timestamp,user,type,severity,file,ip,action_taken,resolved\n';
    const csv = rows.map(r =>
      `${r.created_at},${r.email || ''},${r.violation_type},${r.severity},${r.file || ''},${r.ip_address || ''},${r.action_taken || ''},${r.resolved}`
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="violations.csv"');
    res.send(header + csv);
  } catch (err) { next(err); }
});

/* ─── Heatmap by hour/day ────────────────────────────────────────────────── */
router.get('/heatmap', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT EXTRACT(DOW FROM created_at) AS dow,
              EXTRACT(HOUR FROM created_at) AS hour,
              COUNT(*) AS count
       FROM drm_violations
       WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30d'
       GROUP BY dow, hour ORDER BY dow, hour`,
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ════════════════════ ALERT RULES ═══════════════════════════════════════════ */
router.get('/alert-rules', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT * FROM alert_rules WHERE tenant_id=$1 ORDER BY created_at DESC',
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/alert-rules', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, condition, action, severity = 'medium' } = req.body;
    const { rows } = await query(
      `INSERT INTO alert_rules (id, tenant_id, name, condition, action, severity)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [uuid(), req.user.tenantId, name, JSON.stringify(condition), JSON.stringify(action), severity]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/alert-rules/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, condition, action, severity, active } = req.body;
    await query(
      `UPDATE alert_rules SET
         name=COALESCE($1,name), condition=COALESCE($2,condition),
         action=COALESCE($3,action), severity=COALESCE($4,severity),
         active=COALESCE($5,active)
       WHERE id=$6`,
      [name, condition ? JSON.stringify(condition) : null,
       action ? JSON.stringify(action) : null,
       severity, active, req.params.id]
    );
    res.json({ message: 'Alert rule updated' });
  } catch (err) { next(err); }
});

router.delete('/alert-rules/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    await query('DELETE FROM alert_rules WHERE id=$1', [req.params.id]);
    res.json({ message: 'Alert rule deleted' });
  } catch (err) { next(err); }
});

/* ─── Evaluate alert rules against recent violations (called by cron) ──── */
async function evaluateAlertRules(tenantId) {
  const { rows: rules } = await query(
    'SELECT * FROM alert_rules WHERE tenant_id=$1 AND active=TRUE', [tenantId]
  );
  for (const rule of rules) {
    const cond = rule.condition;
    // Simple threshold rule: { type: 'count', metric: 'violations', window: '1h', threshold: 10 }
    if (cond.type === 'count') {
      const { rows } = await query(
        `SELECT COUNT(*) FROM drm_violations WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '1 hour'`,
        [tenantId]
      );
      if (parseInt(rows[0].count) >= (cond.threshold || 10)) {
        await query(
          'UPDATE alert_rules SET triggered=triggered+1, last_triggered_at=NOW() WHERE id=$1', [rule.id]
        );
        // Fire configured action (webhook, email, etc.)
      }
    }
  }
}

module.exports = router;
module.exports.evaluateAlertRules = evaluateAlertRules;
