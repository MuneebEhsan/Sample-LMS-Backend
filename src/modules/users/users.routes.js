'use strict';
/**
 * @swagger
 * tags: [{ name: Users, description: User management (Phase 1) }]
 */
const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const multer  = require('multer');
const { v4: uuid } = require('uuid');
const { query }    = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { paginate, paginatedResponse, sortClause } = require('../../common/utils/pagination');
const { auditLog } = require('../../common/utils/audit');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

/* ─── GET /users ──────────────────────────────────────────────────────────── */
/**
 * @swagger
 * /users:
 *   get:
 *     summary: List all users (Admin+)
 *     tags: [Users]
 *     parameters:
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *       - in: query
 *         name: role
 *         schema: { type: string }
 *       - in: query
 *         name: status
 *         schema: { type: string, enum: [active, suspended, inactive] }
 *       - in: query
 *         name: page
 *         schema: { type: integer }
 *       - in: query
 *         name: limit
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Paginated user list
 */
router.get('/', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { search, status, role, tenantId } = req.query;
    const tid = tenantId || req.user.tenantId;

    let conditions = ['1=1'];
    let params     = [];
    let p          = 1;

    if (tid)    { conditions.push(`u.tenant_id=$${p++}`); params.push(tid); }
    if (status) { conditions.push(`u.status=$${p++}`);    params.push(status); }
    if (search) {
      conditions.push(`(u.email ILIKE $${p} OR u.first_name ILIKE $${p} OR u.last_name ILIKE $${p})`);
      params.push(`%${search}%`); p++;
    }
    if (role) {
      conditions.push(`EXISTS (SELECT 1 FROM user_roles ur2 JOIN roles r2 ON r2.id=ur2.role_id WHERE ur2.user_id=u.id AND r2.name=$${p++})`);
      params.push(role);
    }

    const WHERE = conditions.join(' AND ');
    const sort  = sortClause(req, ['email','first_name','created_at','last_login_at']);

    const countRes = await query(`SELECT COUNT(*) FROM users u WHERE ${WHERE}`, params);
    const total    = parseInt(countRes.rows[0].count);

    const { rows } = await query(
      `SELECT u.id, u.email, u.first_name, u.last_name, u.avatar_url, u.status,
              u.two_fa_enabled, u.email_verified, u.last_login_at, u.created_at,
              COALESCE(json_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '[]') AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r       ON r.id = ur.role_id
       WHERE ${WHERE}
       GROUP BY u.id
       ${sort} LIMIT $${p++} OFFSET $${p++}`,
      [...params, limit, offset]
    );

    res.json(paginatedResponse(rows, total, page, limit));
  } catch (err) { next(err); }
});

/* ─── GET /users/:id ─────────────────────────────────────────────────────── */
router.get('/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT u.id, u.email, u.first_name, u.last_name, u.avatar_url, u.bio,
              u.timezone, u.language, u.status, u.two_fa_enabled, u.email_verified,
              u.last_login_at, u.last_login_ip, u.created_at,
              COALESCE(json_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '[]') AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r       ON r.id = ur.role_id
       WHERE u.id=$1
       GROUP BY u.id`, [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

/* ─── POST /users ────────────────────────────────────────────────────────── */
router.post('/', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { email, password, firstName, lastName, roleNames = ['Student'], tenantId, status = 'active' } = req.body;
    const tid = tenantId || req.user.tenantId;

    const existing = await query('SELECT id FROM users WHERE email=$1 AND tenant_id=$2', [email, tid]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password || Math.random().toString(36), 12);
    const { rows } = await query(
      `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, status, email_verified)
       VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE) RETURNING *`,
      [uuid(), tid, email, hash, firstName, lastName, status]
    );
    const user = rows[0];

    // Assign roles
    for (const roleName of roleNames) {
      const { rows: roleRows } = await query('SELECT id FROM roles WHERE name=$1', [roleName]);
      if (roleRows.length) {
        await query('INSERT INTO user_roles (user_id, role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
          [user.id, roleRows[0].id]);
      }
    }

    await auditLog({ userId: req.user.id, tenantId: tid, action: 'user.create', resourceId: user.id, ip: req.ip });
    res.status(201).json({ id: user.id, email: user.email, status: user.status });
  } catch (err) { next(err); }
});

/* ─── PATCH /users/:id ───────────────────────────────────────────────────── */
router.patch('/:id', auth, async (req, res, next) => {
  try {
    const isSelf  = req.params.id === req.user.id;
    const isAdmin = req.user.roles?.includes('Super Admin') || req.user.roles?.includes('Admin');
    if (!isSelf && !isAdmin) return res.status(403).json({ error: 'Forbidden' });

    const allowed = ['first_name','last_name','bio','timezone','language','avatar_url'];
    if (isAdmin) allowed.push('status');

    const fields = [], values = [];
    let p = 1;
    for (const key of allowed) {
      if (req.body[key] !== undefined) { fields.push(`${key}=$${p++}`); values.push(req.body[key]); }
    }
    if (!fields.length) return res.status(400).json({ error: 'No valid fields to update' });

    values.push(req.params.id);
    await query(`UPDATE users SET ${fields.join(',')}, updated_at=NOW() WHERE id=$${p}`, values);
    await auditLog({ userId: req.user.id, action: 'user.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'User updated' });
  } catch (err) { next(err); }
});

/* ─── PATCH /users/:id/password ──────────────────────────────────────────── */
router.patch('/:id/password', auth, async (req, res, next) => {
  try {
    if (req.params.id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    const { currentPassword, newPassword } = req.body;
    const { rows } = await query('SELECT password_hash FROM users WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    const valid = await bcrypt.compare(currentPassword, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password incorrect' });

    const hash = await bcrypt.hash(newPassword, 12);
    await query('UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2', [hash, req.params.id]);
    await query('DELETE FROM sessions WHERE user_id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'user.password.change', ip: req.ip });
    res.json({ message: 'Password updated — all sessions revoked' });
  } catch (err) { next(err); }
});

/* ─── PATCH /users/:id/roles ─────────────────────────────────────────────── */
router.patch('/:id/roles', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { roles } = req.body;
    await query('DELETE FROM user_roles WHERE user_id=$1', [req.params.id]);
    for (const roleName of roles) {
      const { rows } = await query('SELECT id FROM roles WHERE name=$1', [roleName]);
      if (rows.length) await query('INSERT INTO user_roles (user_id, role_id) VALUES ($1,$2)', [req.params.id, rows[0].id]);
    }
    await auditLog({ userId: req.user.id, action: 'user.roles.update', resourceId: req.params.id, detail: { roles }, ip: req.ip });
    res.json({ message: 'Roles updated' });
  } catch (err) { next(err); }
});

/* ─── DELETE /users/:id ──────────────────────────────────────────────────── */
router.delete('/:id', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    await query('UPDATE users SET status=$1, updated_at=NOW() WHERE id=$2', ['deleted', req.params.id]);
    await query('DELETE FROM sessions WHERE user_id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'user.delete', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'User deleted' });
  } catch (err) { next(err); }
});

/* ─── GET /users/export ──────────────────────────────────────────────────── */
router.get('/export/csv', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT u.email, u.first_name, u.last_name, u.status, u.email_verified,
              u.two_fa_enabled, u.created_at,
              COALESCE(string_agg(DISTINCT r.name, ','), '') AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.tenant_id=$1
       GROUP BY u.id`, [req.user.tenantId]
    );
    const header = 'email,first_name,last_name,status,email_verified,two_fa_enabled,created_at,roles\n';
    const csv    = rows.map(r =>
      `${r.email},${r.first_name},${r.last_name},${r.status},${r.email_verified},${r.two_fa_enabled},${r.created_at},${r.roles}`
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
    res.send(header + csv);
  } catch (err) { next(err); }
});

/* ─── GET /users/roles/list ──────────────────────────────────────────────── */
router.get('/roles/list', auth, async (req, res, next) => {
  try {
    const { rows } = await query('SELECT id, name, description, permissions, is_system FROM roles ORDER BY name');
    res.json(rows);
  } catch (err) { next(err); }
});

module.exports = router;
