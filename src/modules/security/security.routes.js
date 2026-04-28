'use strict';
const router = require('express').Router();
const { v4: uuid } = require('uuid');
const { query }    = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../common/utils/pagination');
const { auditLog } = require('../../common/utils/audit');

/* ════════════════════ IP RULES ══════════════════════════════════════════════ */
router.get('/ip-rules', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT * FROM ip_rules WHERE tenant_id=$1 ORDER BY created_at DESC',
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/ip-rules', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { type, cidr, reason } = req.body;
    if (!['allowlist','blocklist'].includes(type))
      return res.status(400).json({ error: 'type must be allowlist or blocklist' });
    const { rows } = await query(
      'INSERT INTO ip_rules (id, tenant_id, type, cidr, reason, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [uuid(), req.user.tenantId, type, cidr, reason, req.user.id]
    );
    await auditLog({ userId: req.user.id, action: 'security.ip_rule.create', detail: { type, cidr }, ip: req.ip });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.delete('/ip-rules/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    await query('UPDATE ip_rules SET active=FALSE WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user.tenantId]);
    await auditLog({ userId: req.user.id, action: 'security.ip_rule.delete', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'IP rule removed' });
  } catch (err) { next(err); }
});

/* ════════════════════ AUDIT LOGS ════════════════════════════════════════════ */
router.get('/audit-logs', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { search, userId, action, from, to, resource } = req.query;

    let conds = ['al.tenant_id=$1'], params = [req.user.tenantId], p = 2;
    if (userId)   { conds.push(`al.user_id=$${p++}`);    params.push(userId); }
    if (action)   { conds.push(`al.action ILIKE $${p++}`); params.push(`%${action}%`); }
    if (resource) { conds.push(`al.resource=$${p++}`);   params.push(resource); }
    if (from)     { conds.push(`al.created_at>=$${p++}`);params.push(from); }
    if (to)       { conds.push(`al.created_at<=$${p++}`);params.push(to); }
    if (search) {
      conds.push(`(al.action ILIKE $${p} OR al.ip_address ILIKE $${p})`);
      params.push(`%${search}%`); p++;
    }
    const WHERE = conds.join(' AND ');

    const { rows } = await query(
      `SELECT al.*,
              u.email AS user_email,
              u.first_name || ' ' || u.last_name AS user_name
       FROM audit_logs al
       LEFT JOIN users u ON u.id = al.user_id
       WHERE ${WHERE}
       ORDER BY al.created_at DESC LIMIT $${p++} OFFSET $${p++}`,
      [...params, limit, offset]
    );
    const cnt = await query(`SELECT COUNT(*) FROM audit_logs al WHERE ${WHERE}`, params);
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

/* ─── Export audit logs as CSV ──────────────────────────────────────────── */
router.get('/audit-logs/export', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { from, to } = req.query;
    const { rows } = await query(
      `SELECT al.created_at, u.email, al.action, al.resource, al.resource_id, al.ip_address
       FROM audit_logs al LEFT JOIN users u ON u.id=al.user_id
       WHERE al.tenant_id=$1 AND ($2::date IS NULL OR al.created_at>=$2) AND ($3::date IS NULL OR al.created_at<=$3)
       ORDER BY al.created_at DESC LIMIT 10000`,
      [req.user.tenantId, from || null, to || null]
    );
    const header = 'timestamp,user,action,resource,resource_id,ip\n';
    const csv    = rows.map(r =>
      `${r.created_at},${r.email || ''},${r.action},${r.resource || ''},${r.resource_id || ''},${r.ip_address || ''}`
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="audit-logs.csv"');
    res.send(header + csv);
  } catch (err) { next(err); }
});

/* ════════════════════ APPEARANCE ════════════════════════════════════════════ */
router.get('/appearance', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT * FROM appearance WHERE tenant_id=$1', [req.user.tenantId]
    );
    res.json(rows[0] || {
      primaryColor: '#F59E0B', secondaryColor: '#6366F1', accentColor: '#14B8A6',
      fontFamily: 'Plus Jakarta Sans', darkMode: true,
    });
  } catch (err) { next(err); }
});

router.put('/appearance', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const {
      primaryColor, secondaryColor, accentColor, fontFamily,
      logoUrl, faviconUrl, loginBgUrl, customCss, customJs, darkMode,
    } = req.body;
    await query(
      `INSERT INTO appearance (id, tenant_id, primary_color, secondary_color, accent_color,
         font_family, logo_url, favicon_url, login_bg_url, custom_css, custom_js, dark_mode)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (tenant_id) DO UPDATE SET
         primary_color=$3, secondary_color=$4, accent_color=$5,
         font_family=$6, logo_url=$7, favicon_url=$8, login_bg_url=$9,
         custom_css=$10, custom_js=$11, dark_mode=$12, updated_at=NOW()`,
      [uuid(), req.user.tenantId, primaryColor, secondaryColor, accentColor,
       fontFamily, logoUrl, faviconUrl, loginBgUrl, customCss, customJs, darkMode]
    );
    await auditLog({ userId: req.user.id, action: 'appearance.update', ip: req.ip });
    res.json({ message: 'Appearance saved' });
  } catch (err) { next(err); }
});

/* ════════════════════ PASSWORD POLICY ══════════════════════════════════════ */
router.get('/password-policy', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  res.json({
    minLength:        8,
    requireUppercase: true,
    requireNumbers:   true,
    requireSpecial:   true,
    expiryDays:       90,
    historyCount:     5,
    maxFailedLogins:  5,
    lockoutMinutes:   15,
  });
});

/* ════════════════════ GDPR ══════════════════════════════════════════════════ */
router.post('/gdpr/export/:userId', auth, async (req, res, next) => {
  try {
    const { userId } = req.params;
    if (userId !== req.user.id) {
      const { rows: roles } = await query(
        `SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1`,
        [req.user.id]
      );
      const isAdmin = roles.some(r => ['Super Admin','Admin'].includes(r.name));
      if (!isAdmin) return res.status(403).json({ error: 'Forbidden' });
    }

    const [userRes, enrollRes, orderRes, gradeRes, msgRes] = await Promise.all([
      query('SELECT id, email, first_name, last_name, bio, timezone, language, created_at FROM users WHERE id=$1', [userId]),
      query('SELECT c.title, e.enrolled_at, e.progress_pct FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.user_id=$1', [userId]),
      query('SELECT amount, currency, status, created_at FROM orders WHERE user_id=$1', [userId]),
      query(`SELECT gi.name, g.final_grade FROM grades g JOIN grade_items gi ON gi.id=g.grade_item_id WHERE g.user_id=$1`, [userId]),
      query('SELECT body, created_at FROM messages WHERE sender_id=$1 AND deleted_at IS NULL', [userId]),
    ]);

    await auditLog({ userId: req.user.id, action: 'gdpr.export', resourceId: userId, ip: req.ip });
    res.json({
      exportedAt: new Date().toISOString(),
      user:        userRes.rows[0],
      enrollments: enrollRes.rows,
      orders:      orderRes.rows,
      grades:      gradeRes.rows,
      messages:    msgRes.rows,
    });
  } catch (err) { next(err); }
});

router.delete('/gdpr/erase/:userId', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    const { userId } = req.params;
    // Anonymise PII rather than hard delete (GDPR-safe)
    await query(
      `UPDATE users SET
         email=CONCAT('deleted_',$1,'@erased.local'),
         first_name='[Deleted]', last_name='[Deleted]',
         password_hash=NULL, avatar_url=NULL, bio=NULL,
         two_fa_secret=NULL, two_fa_enabled=FALSE, google_id=NULL, status='deleted'
       WHERE id=$1`, [userId]
    );
    await query('DELETE FROM sessions WHERE user_id=$1', [userId]);
    await auditLog({ userId: req.user.id, action: 'gdpr.erase', resourceId: userId, ip: req.ip });
    res.json({ message: 'User data erased (GDPR)' });
  } catch (err) { next(err); }
});

/* ════════════════════ SECURITY DASHBOARD ═══════════════════════════════════ */
router.get('/overview', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const [lockouts, ipRules, recentLogins, failedLogins] = await Promise.all([
      query(`SELECT COUNT(*) FROM users WHERE locked_until > NOW() AND tenant_id=$1`, [req.user.tenantId]),
      query(`SELECT type, COUNT(*) FROM ip_rules WHERE tenant_id=$1 AND active=TRUE GROUP BY type`, [req.user.tenantId]),
      query(`SELECT COUNT(*) FROM audit_logs WHERE action='auth.login' AND tenant_id=$1 AND created_at > NOW()-INTERVAL '24h'`, [req.user.tenantId]),
      query(`SELECT COUNT(*) FROM audit_logs WHERE action='auth.login.failed' AND tenant_id=$1 AND created_at > NOW()-INTERVAL '24h'`, [req.user.tenantId]),
    ]);
    res.json({
      lockedAccounts:   parseInt(lockouts.rows[0].count),
      ipRules:          Object.fromEntries(ipRules.rows.map(r => [r.type, parseInt(r.count)])),
      loginsLast24h:    parseInt(recentLogins.rows[0].count),
      failedLoginsLast24h: parseInt(failedLogins.rows[0].count),
    });
  } catch (err) { next(err); }
});

module.exports = router;
