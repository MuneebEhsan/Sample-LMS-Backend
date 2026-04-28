'use strict';
/**
 * Multi-Tenancy Routes
 * ─────────────────────────────────────────────────────────────────────────────
 * RULE: ONLY Super Admin can CREATE tenants.
 *       Tenant Admins can UPDATE settings within their own tenant only.
 *       No other role has any access to these endpoints.
 */
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');
const { query }    = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../common/utils/pagination');
const { auditLog } = require('../../common/utils/audit');
const { sendEmail, welcomeTenantAdminTemplate } = require('../../common/utils/mailer');
const logger = require('../../common/utils/logger');

// ── Guard: reject everyone except Super Admin ────────────────────────────────
const superAdminOnly = requireRole('Super Admin');

// ── Guard: Super Admin OR Tenant Admin (for own tenant only) ─────────────────
function superAdminOrOwnTenant(req, res, next) {
  const isSuperAdmin   = (req.user.roles || []).includes('Super Admin');
  const isTenantAdmin  = (req.user.roles || []).includes('Admin') ||
                         (req.user.roles || []).includes('Tenant Admin');
  if (isSuperAdmin) return next();
  if (isTenantAdmin && req.params.id === req.user.tenantId) return next();
  return res.status(403).json({
    error: 'Forbidden — only Super Admin can manage other tenants',
    code:  'SUPER_ADMIN_ONLY',
  });
}

/* ══════════════════════════════════════════════════════════════════════════════
   LIST TENANTS — Super Admin only
══════════════════════════════════════════════════════════════════════════════ */
router.get('/', auth, superAdminOnly, async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { search, status, plan } = req.query;

    let conds = [], params = [], p = 1;
    if (status) { conds.push(`t.status=$${p++}`); params.push(status); }
    if (plan)   { conds.push(`t.plan=$${p++}`);   params.push(plan); }
    if (search) {
      conds.push(`(t.name ILIKE $${p} OR t.slug ILIKE $${p})`);
      params.push(`%${search}%`); p++;
    }
    const WHERE = conds.length ? 'WHERE ' + conds.join(' AND ') : '';

    const { rows } = await query(`
      SELECT t.*,
             COUNT(DISTINCT u.id) FILTER (WHERE u.status != 'deleted') AS user_count,
             COUNT(DISTINCT c.id)                                       AS course_count,
             COUNT(DISTINCT co.id) FILTER (WHERE co.category_id IS NOT NULL) AS category_count,
             COALESCE(SUM(o.amount) FILTER (WHERE o.status='completed'), 0) AS total_revenue
      FROM tenants t
      LEFT JOIN users   u ON u.tenant_id = t.id
      LEFT JOIN courses c ON c.tenant_id = t.id
      LEFT JOIN categories co ON co.tenant_id = t.id
      LEFT JOIN orders  o ON o.tenant_id = t.id
      ${WHERE}
      GROUP BY t.id
      ORDER BY t.created_at DESC
      LIMIT $${p++} OFFSET $${p++}
    `, [...params, limit, offset]);

    const cnt = await query(`SELECT COUNT(*) FROM tenants t ${WHERE}`, params);
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   GET ONE TENANT — Super Admin only
══════════════════════════════════════════════════════════════════════════════ */
router.get('/:id', auth, superAdminOrOwnTenant, async (req, res, next) => {
  try {
    const { rows } = await query(`
      SELECT t.*,
             COUNT(DISTINCT u.id) FILTER (WHERE u.status != 'deleted') AS user_count,
             COUNT(DISTINCT c.id)                                       AS course_count,
             (SELECT row_to_json(sp.*) FROM storage_providers sp
              WHERE sp.tenant_id = t.id AND sp.is_default = TRUE LIMIT 1) AS storage_config
      FROM tenants t
      LEFT JOIN users   u ON u.tenant_id = t.id
      LEFT JOIN courses c ON c.tenant_id = t.id
      WHERE t.id = $1
      GROUP BY t.id
    `, [req.params.id]);

    if (!rows.length) return res.status(404).json({ error: 'Tenant not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   CREATE TENANT — SUPER ADMIN ONLY
   Includes: admin account creation + cloud storage config
══════════════════════════════════════════════════════════════════════════════ */
router.post('/', auth, superAdminOnly, async (req, res, next) => {
  try {
    const {
      // ── Organisation
      name,
      plan            = 'Pro',
      color           = '#6366F1',
      logoUrl,
      subdomain,
      customDomain,
      timezone        = 'UTC',
      settings        = {},

      // ── Admin account (required)
      adminEmail,
      adminPassword,
      adminFirstName  = 'Admin',
      adminLastName   = '',
      adminJobTitle,
      sendWelcomeEmail = true,

      // ── Storage (optional — can be configured later)
      storageProvider = 'r2',
      storageConfig   = {},
      storageQuotaGb  = { Starter:10, Growth:100, Pro:500, Enterprise:5000 }[plan] || 500,
      maxFileSizeMb   = 2048,
    } = req.body;

    // ── Validation
    if (!name)          return res.status(400).json({ error: 'name is required' });
    if (!adminEmail)    return res.status(400).json({ error: 'adminEmail is required' });
    if (!adminPassword || adminPassword.length < 8)
      return res.status(400).json({ error: 'adminPassword must be at least 8 characters' });

    const slug = (subdomain || name)
      .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
      + '-' + Date.now().toString(36);

    /* 1. Create tenant ──────────────────────────────────────────────────── */
    const tenantId = uuid();
    const { rows: tenantRows } = await query(`
      INSERT INTO tenants (id, name, slug, plan, color, logo_url, subdomain, custom_domain, status, settings)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)
      RETURNING *
    `, [tenantId, name, slug, plan, color, logoUrl, slug, customDomain,
        JSON.stringify({ timezone, storageProvider, storageQuotaGb, maxFileSizeMb, adminJobTitle, ...settings })]);
    const tenant = tenantRows[0];

    /* 2. Create tenant admin user ──────────────────────────────────────── */
    const hash    = await bcrypt.hash(adminPassword, 12);
    const adminId = uuid();
    const { rows: adminRows } = await query(`
      INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, status, email_verified)
      VALUES ($1,$2,$3,$4,$5,$6,'active',TRUE)
      RETURNING id, email, first_name, last_name, tenant_id, created_at
    `, [adminId, tenantId, adminEmail.toLowerCase(), hash, adminFirstName, adminLastName]);
    const adminUser = adminRows[0];

    /* 3. Assign 'Admin' role to tenant admin ────────────────────────────── */
    const { rows: roleRows } = await query(
      "SELECT id FROM roles WHERE name='Admin' AND is_system=TRUE LIMIT 1"
    );
    if (roleRows.length) {
      await query(
        'INSERT INTO user_roles (user_id, role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [adminId, roleRows[0].id]
      );
    }

    /* 4. Storage provider config ─────────────────────────────────────────── */
    const STORAGE_LABEL = {
      r2: 'Cloudflare R2', s3: 'AWS S3', azure: 'Azure Blob',
      gcs: 'Google Cloud Storage', backblaze: 'Backblaze B2', local: 'Local Server',
    };
    await query(`
      INSERT INTO storage_providers (id, tenant_id, name, type, config, is_default, active)
      VALUES ($1,$2,$3,$4,$5,TRUE,TRUE)
    `, [uuid(), tenantId,
        `${name} — ${STORAGE_LABEL[storageProvider] || storageProvider}`,
        storageProvider,
        JSON.stringify({ ...storageConfig, quotaGb: storageQuotaGb, maxFileMb: maxFileSizeMb })
    ]);

    /* 5. Default appearance ─────────────────────────────────────────────── */
    await query(
      'INSERT INTO appearance (id, tenant_id, primary_color, dark_mode) VALUES ($1,$2,$3,TRUE) ON CONFLICT DO NOTHING',
      [uuid(), tenantId, color]
    );

    /* 6. Default DRM license profiles ───────────────────────────────────── */
    const profiles = [
      ['Starter',    '#6B7280', 'starter',    1, 1, false, false, 3600],
      ['Standard',   '#F59E0B', 'standard',   3, 2, true,  true,  3600],
      ['Premium',    '#8B5CF6', 'premium',    5, 3, true,  true,  7200],
      ['Enterprise', '#EF4444', 'enterprise', 10, 5, true,  true,  1800],
    ];
    for (const [pname, pcolor, tier, maxDev, maxStr, wm, sb, ttl] of profiles) {
      await query(`
        INSERT INTO license_profiles
          (id, tenant_id, name, color, tier, max_devices, max_streams,
           watermark_enabled, screen_block, token_ttl_seconds)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING
      `, [uuid(), tenantId, pname, pcolor, tier, maxDev, maxStr, wm, sb, ttl]);
    }

    /* 7. Welcome email ──────────────────────────────────────────────────── */
    if (sendWelcomeEmail) {
      const loginUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login`;
      const tmpl = welcomeTenantAdminTemplate(
        `${adminFirstName} ${adminLastName}`.trim(),
        name, adminEmail, adminPassword, loginUrl
      );
      sendEmail({ to: adminEmail, ...tmpl })
        .catch(e => logger.warn(`[mailer] Welcome email failed: ${e.message}`));
    }

    /* 8. Audit ──────────────────────────────────────────────────────────── */
    await auditLog({
      userId: req.user.id, tenantId, action: 'tenant.create',
      resourceId: tenantId,
      detail: { name, plan, adminEmail, storageProvider, storageQuotaGb },
      ip: req.ip,
    });

    res.status(201).json({
      tenant,
      admin: { ...adminUser, role: 'Admin' },
      storageProvider,
      storageQuotaGb,
      message: `Tenant "${name}" created. Admin: ${adminEmail}`,
    });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Tenant subdomain already taken' });
    next(err);
  }
});

/* ══════════════════════════════════════════════════════════════════════════════
   UPDATE TENANT SETTINGS
   Super Admin: can update ANY tenant
   Tenant Admin: can update ONLY their own tenant (limited fields)
══════════════════════════════════════════════════════════════════════════════ */
router.patch('/:id', auth, superAdminOrOwnTenant, async (req, res, next) => {
  try {
    const isSuperAdmin = (req.user.roles || []).includes('Super Admin');

    // Fields Tenant Admin is NOT allowed to change
    const adminForbiddenFields = ['plan', 'status', 'slug', 'subdomain'];
    if (!isSuperAdmin) {
      for (const f of adminForbiddenFields) {
        if (req.body[f] !== undefined) {
          return res.status(403).json({
            error: `Tenant Admin cannot change "${f}" — contact Super Admin`,
            code: 'SUPER_ADMIN_ONLY',
          });
        }
      }
    }

    const { name, plan, color, status, logoUrl, subdomain, customDomain, settings } = req.body;

    await query(`
      UPDATE tenants SET
        name          = COALESCE($1, name),
        plan          = COALESCE($2, plan),
        color         = COALESCE($3, color),
        status        = COALESCE($4, status),
        logo_url      = COALESCE($5, logo_url),
        subdomain     = COALESCE($6, subdomain),
        custom_domain = COALESCE($7, custom_domain),
        settings      = COALESCE($8::jsonb, settings),
        updated_at    = NOW()
      WHERE id = $9
    `, [name, isSuperAdmin ? plan : null, color,
        isSuperAdmin ? status : null,
        logoUrl, isSuperAdmin ? subdomain : null,
        customDomain, settings ? JSON.stringify(settings) : null,
        req.params.id]);

    await auditLog({ userId: req.user.id, action: 'tenant.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Tenant updated' });
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   SUSPEND TENANT — Super Admin only
══════════════════════════════════════════════════════════════════════════════ */
router.delete('/:id', auth, superAdminOnly, async (req, res, next) => {
  try {
    if (req.params.id === req.user.tenantId)
      return res.status(400).json({ error: 'Cannot suspend your own tenant' });

    await query("UPDATE tenants SET status='suspended', updated_at=NOW() WHERE id=$1", [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'tenant.suspend', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Tenant suspended' });
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   REACTIVATE TENANT — Super Admin only
══════════════════════════════════════════════════════════════════════════════ */
router.post('/:id/activate', auth, superAdminOnly, async (req, res, next) => {
  try {
    await query("UPDATE tenants SET status='active', updated_at=NOW() WHERE id=$1", [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'tenant.activate', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Tenant activated' });
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   STATS — Super Admin only
══════════════════════════════════════════════════════════════════════════════ */
router.get('/:id/stats', auth, superAdminOnly, async (req, res, next) => {
  try {
    const tid = req.params.id;
    const [users, courses, orders, violations, storage, cats] = await Promise.all([
      query("SELECT COUNT(*) total, COUNT(*) FILTER(WHERE status='active') active FROM users WHERE tenant_id=$1", [tid]),
      query("SELECT COUNT(*) total, COUNT(*) FILTER(WHERE status='published') published FROM courses WHERE tenant_id=$1", [tid]),
      query("SELECT COUNT(*) total, COALESCE(SUM(amount) FILTER(WHERE status='completed'),0) revenue FROM orders WHERE tenant_id=$1", [tid]),
      query("SELECT COUNT(*) FROM drm_violations WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30d'", [tid]),
      query("SELECT COALESCE(SUM(file_size_bytes),0) total_bytes, COUNT(*) total_files FROM protected_files WHERE tenant_id=$1", [tid]),
      query("SELECT COUNT(*) FROM categories WHERE tenant_id=$1", [tid]),
    ]);
    res.json({
      users:        { total: parseInt(users.rows[0].total), active: parseInt(users.rows[0].active) },
      courses:      { total: parseInt(courses.rows[0].total), published: parseInt(courses.rows[0].published) },
      revenue:      parseFloat(orders.rows[0].revenue),
      orders:       parseInt(orders.rows[0].total),
      violations:   parseInt(violations.rows[0].count),
      storage:      { bytes: parseInt(storage.rows[0].total_bytes), files: parseInt(storage.rows[0].total_files) },
      categories:   parseInt(cats.rows[0].count),
    });
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   STORAGE CONFIG — Super Admin only
══════════════════════════════════════════════════════════════════════════════ */
router.get('/:id/storage', auth, superAdminOnly, async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT id, name, type, is_default, active, created_at FROM storage_providers WHERE tenant_id=$1 ORDER BY is_default DESC',
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.patch('/:id/storage', auth, superAdminOnly, async (req, res, next) => {
  try {
    const { storageProvider, storageConfig = {}, storageQuotaGb = 500, maxFileSizeMb = 2048 } = req.body;
    const existing = await query(
      'SELECT id FROM storage_providers WHERE tenant_id=$1 AND is_default=TRUE LIMIT 1',
      [req.params.id]
    );
    if (existing.rows.length) {
      await query(
        'UPDATE storage_providers SET type=$1, config=$2, updated_at=NOW() WHERE id=$3',
        [storageProvider,
         JSON.stringify({ ...storageConfig, quotaGb: storageQuotaGb, maxFileMb: maxFileSizeMb }),
         existing.rows[0].id]
      );
    } else {
      await query(
        'INSERT INTO storage_providers (id, tenant_id, name, type, config, is_default, active) VALUES ($1,$2,$3,$4,$5,TRUE,TRUE)',
        [uuid(), req.params.id, `Storage — ${storageProvider}`, storageProvider,
         JSON.stringify({ ...storageConfig, quotaGb: storageQuotaGb, maxFileMb: maxFileSizeMb })]
      );
    }
    await auditLog({ userId: req.user.id, action: 'tenant.storage.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Storage config updated' });
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   BILLING PLANS — public reference
══════════════════════════════════════════════════════════════════════════════ */
router.get('/billing/plans', auth, (_req, res) => {
  res.json([
    { id:'Starter',    price:49,   maxUsers:100,    maxCourses:20,    maxStorageGb:10,   drm:false, sso:false },
    { id:'Growth',     price:149,  maxUsers:500,    maxCourses:100,   maxStorageGb:100,  drm:true,  sso:false },
    { id:'Pro',        price:399,  maxUsers:2000,   maxCourses:500,   maxStorageGb:500,  drm:true,  sso:true  },
    { id:'Enterprise', price:999,  maxUsers:999999, maxCourses:999999,maxStorageGb:5000, drm:true,  sso:true, multiTenant:true },
  ]);
});

module.exports = router;
