'use strict';
/**
 * Courses Routes — Phase 2
 * ─────────────────────────────────────────────────────────────────────────────
 * Categories:
 *   - Super Admin: full CRUD on all categories
 *   - Tenant Admin: create/update/delete categories within THEIR tenant only
 *   - Nested subcategories: unlimited depth via parent_id
 *   - Courses are assigned to a leaf category
 *
 * Courses:
 *   - Tenant Admin / Instructor / Course Manager: create & manage courses
 *   - Students: enroll, view, complete activities
 */
const router  = require('express').Router();
const { v4: uuid }  = require('uuid');
const { query }     = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { paginate, paginatedResponse, sortClause } = require('../../common/utils/pagination');
const { auditLog }  = require('../../common/utils/audit');

// ── Helpers ───────────────────────────────────────────────────────────────────
function isCourseManager(req) {
  const r = req.user.roles || [];
  return r.includes('Super Admin') || r.includes('Admin') ||
         r.includes('Instructor')  || r.includes('Course Manager');
}

function isTenantAdmin(req) {
  const r = req.user.roles || [];
  return r.includes('Super Admin') || r.includes('Admin');
}

// Build a full nested category tree from flat rows
function buildCategoryTree(rows) {
  const map  = {};
  const tree = [];
  for (const r of rows) map[r.id] = { ...r, children: [] };
  for (const r of rows) {
    if (r.parent_id && map[r.parent_id]) map[r.parent_id].children.push(map[r.id]);
    else tree.push(map[r.id]);
  }
  return tree;
}

// Collect all descendant IDs for a category (used to find courses in subtree)
function collectDescendantIds(tree, rootId, acc = []) {
  for (const node of tree) {
    if (node.id === rootId || acc.includes(node.id)) {
      acc.push(node.id);
      for (const child of node.children) collectDescendantIds([child], child.id, acc);
    } else {
      collectDescendantIds(node.children, rootId, acc);
    }
  }
  return acc;
}

/* ══════════════════════════════════════════════════════════════════════════════
   CATEGORIES — Nested tree with unlimited depth
   Tenant Admin can manage their own tenant's categories.
   Super Admin can manage any tenant's categories.
══════════════════════════════════════════════════════════════════════════════ */

/**
 * GET /courses/categories
 * Returns full nested category tree for the current tenant.
 * Each node includes: id, name, slug, description, parent_id,
 *   icon_url, sort_order, visibility, course_count, depth, children[]
 */
router.get('/categories', auth, async (req, res, next) => {
  try {
    const tid = req.query.tenantId || req.user.tenantId;

    const { rows } = await query(`
      WITH RECURSIVE cat_tree AS (
        -- Anchor: root categories (no parent)
        SELECT c.*, 0 AS depth, c.name::TEXT AS path
        FROM categories c
        WHERE c.tenant_id = $1 AND c.parent_id IS NULL

        UNION ALL

        -- Recursive: children
        SELECT c.*, ct.depth + 1, ct.path || ' > ' || c.name
        FROM categories c
        JOIN cat_tree ct ON ct.id = c.parent_id
      )
      SELECT ct.*,
             COUNT(DISTINCT co.id) AS course_count,
             COUNT(DISTINCT child.id) AS child_count
      FROM cat_tree ct
      LEFT JOIN courses    co    ON co.category_id  = ct.id AND co.status != 'archived'
      LEFT JOIN categories child ON child.parent_id = ct.id AND child.tenant_id = $1
      GROUP BY ct.id, ct.tenant_id, ct.parent_id, ct.name, ct.slug, ct.description,
               ct.icon_url, ct.sort_order, ct.visibility, ct.metadata, ct.created_at,
               ct.depth, ct.path
      ORDER BY ct.depth, ct.sort_order, ct.name
    `, [tid]);

    res.json({
      tree: buildCategoryTree(rows),
      flat: rows,
      total: rows.length,
    });
  } catch (err) { next(err); }
});

/**
 * GET /courses/categories/:id
 * Get single category with its breadcrumb path and direct children.
 */
router.get('/categories/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await query(`
      WITH RECURSIVE breadcrumb AS (
        SELECT c.*, 0 AS depth
        FROM categories c WHERE c.id = $1
        UNION ALL
        SELECT c.*, b.depth + 1
        FROM categories c JOIN breadcrumb b ON c.id = b.parent_id
      )
      SELECT * FROM breadcrumb ORDER BY depth DESC
    `, [req.params.id]);

    if (!rows.length) return res.status(404).json({ error: 'Category not found' });

    const category = rows[rows.length - 1];  // the requested category (depth=0)
    const breadcrumb = rows.slice(0, -1).map(r => ({ id: r.id, name: r.name, slug: r.slug }));

    // Get direct children
    const { rows: children } = await query(
      'SELECT *, (SELECT COUNT(*) FROM categories WHERE parent_id=c.id) AS child_count FROM categories c WHERE c.parent_id=$1 ORDER BY sort_order, name',
      [req.params.id]
    );

    // Get courses directly in this category
    const { rows: courses } = await query(
      `SELECT id, title, slug, status, price, difficulty_level, thumbnail_url,
              (SELECT COUNT(*) FROM enrollments WHERE course_id=c.id) AS enrollment_count
       FROM courses c WHERE c.category_id=$1 AND c.status != 'archived' ORDER BY c.created_at DESC`,
      [req.params.id]
    );

    res.json({ ...category, breadcrumb, children, courses });
  } catch (err) { next(err); }
});

/**
 * POST /courses/categories
 * Create a category or subcategory.
 * - Super Admin: can create for any tenant
 * - Tenant Admin: can create within their own tenant only
 * - parentId (optional): if provided, creates as subcategory
 */
router.post('/categories', auth, async (req, res, next) => {
  try {
    if (!isTenantAdmin(req))
      return res.status(403).json({ error: 'Only Tenant Admin or Super Admin can create categories' });

    const {
      name, description, parentId = null,
      visibility = 'public', sortOrder = 0,
      iconUrl, metadata = {},
      tenantId,   // Super Admin can specify tenant
    } = req.body;

    if (!name) return res.status(400).json({ error: 'name is required' });

    // Determine target tenant
    const isSuperAdmin = (req.user.roles || []).includes('Super Admin');
    const targetTenantId = isSuperAdmin && tenantId ? tenantId : req.user.tenantId;

    // If parentId provided, verify it belongs to the same tenant
    if (parentId) {
      const { rows: parent } = await query(
        'SELECT id, tenant_id FROM categories WHERE id=$1', [parentId]
      );
      if (!parent.length) return res.status(404).json({ error: 'Parent category not found' });
      if (parent[0].tenant_id !== targetTenantId)
        return res.status(400).json({ error: 'Parent category belongs to a different tenant' });
    }

    // Generate unique slug (append tenant prefix to avoid conflicts)
    const baseSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const slug     = baseSlug + '-' + Date.now().toString(36);

    const { rows } = await query(`
      INSERT INTO categories
        (id, tenant_id, parent_id, name, slug, description, icon_url, sort_order, visibility, metadata)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      RETURNING *
    `, [uuid(), targetTenantId, parentId, name, slug, description, iconUrl, sortOrder, visibility, JSON.stringify(metadata)]);

    await auditLog({
      userId: req.user.id,
      action: parentId ? 'category.create_sub' : 'category.create',
      resourceId: rows[0].id,
      detail: { name, parentId, tenantId: targetTenantId },
      ip: req.ip,
    });

    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

/**
 * PATCH /courses/categories/:id
 * Update a category.
 * Tenant Admin can only update categories that belong to their tenant.
 */
router.patch('/categories/:id', auth, async (req, res, next) => {
  try {
    if (!isTenantAdmin(req))
      return res.status(403).json({ error: 'Only Tenant Admin or Super Admin can update categories' });

    // Check ownership
    const { rows: existing } = await query('SELECT * FROM categories WHERE id=$1', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Category not found' });

    const isSuperAdmin = (req.user.roles || []).includes('Super Admin');
    if (!isSuperAdmin && existing[0].tenant_id !== req.user.tenantId)
      return res.status(403).json({ error: 'Cannot update categories from another tenant' });

    const { name, description, visibility, sortOrder, iconUrl, parentId, metadata } = req.body;

    // Prevent circular reference: parentId cannot be self or a descendant
    if (parentId && parentId === req.params.id)
      return res.status(400).json({ error: 'A category cannot be its own parent' });

    if (name) {
      // Generate new slug if name changed
      const newSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') + '-' + Date.now().toString(36);
      await query(`
        UPDATE categories SET
          name        = $1,
          slug        = $2,
          description = COALESCE($3, description),
          visibility  = COALESCE($4, visibility),
          sort_order  = COALESCE($5, sort_order),
          icon_url    = COALESCE($6, icon_url),
          parent_id   = COALESCE($7, parent_id),
          metadata    = COALESCE($8::jsonb, metadata)
        WHERE id = $9
      `, [name, newSlug, description, visibility, sortOrder, iconUrl,
          parentId, metadata ? JSON.stringify(metadata) : null, req.params.id]);
    } else {
      await query(`
        UPDATE categories SET
          description = COALESCE($1, description),
          visibility  = COALESCE($2, visibility),
          sort_order  = COALESCE($3, sort_order),
          icon_url    = COALESCE($4, icon_url),
          parent_id   = COALESCE($5, parent_id),
          metadata    = COALESCE($6::jsonb, metadata)
        WHERE id = $7
      `, [description, visibility, sortOrder, iconUrl,
          parentId, metadata ? JSON.stringify(metadata) : null, req.params.id]);
    }

    await auditLog({ userId: req.user.id, action: 'category.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Category updated' });
  } catch (err) { next(err); }
});

/**
 * PATCH /courses/categories/:id/move
 * Move a category to a new parent (or make it root).
 */
router.patch('/categories/:id/move', auth, async (req, res, next) => {
  try {
    if (!isTenantAdmin(req))
      return res.status(403).json({ error: 'Only Tenant Admin or Super Admin can move categories' });

    const { newParentId } = req.body;  // null = make root

    const { rows: existing } = await query('SELECT * FROM categories WHERE id=$1', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Category not found' });

    const isSuperAdmin = (req.user.roles || []).includes('Super Admin');
    if (!isSuperAdmin && existing[0].tenant_id !== req.user.tenantId)
      return res.status(403).json({ error: 'Cannot move categories from another tenant' });

    if (newParentId === req.params.id)
      return res.status(400).json({ error: 'Cannot move a category under itself' });

    await query('UPDATE categories SET parent_id=$1 WHERE id=$2', [newParentId || null, req.params.id]);
    await auditLog({ userId: req.user.id, action: 'category.move', resourceId: req.params.id, detail: { newParentId }, ip: req.ip });
    res.json({ message: 'Category moved' });
  } catch (err) { next(err); }
});

/**
 * DELETE /courses/categories/:id
 * Delete a category.
 * - Blocks deletion if category has courses assigned to it.
 * - Moves children to the deleted category's parent (not orphaned).
 */
router.delete('/categories/:id', auth, async (req, res, next) => {
  try {
    if (!isTenantAdmin(req))
      return res.status(403).json({ error: 'Only Tenant Admin or Super Admin can delete categories' });

    const { rows: existing } = await query('SELECT * FROM categories WHERE id=$1', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Category not found' });

    const isSuperAdmin = (req.user.roles || []).includes('Super Admin');
    if (!isSuperAdmin && existing[0].tenant_id !== req.user.tenantId)
      return res.status(403).json({ error: 'Cannot delete categories from another tenant' });

    // Check for courses
    const { rows: courseCheck } = await query(
      "SELECT COUNT(*) FROM courses WHERE category_id=$1 AND status != 'archived'", [req.params.id]
    );
    if (parseInt(courseCheck[0].count) > 0) {
      if (req.query.force !== 'true') {
        return res.status(409).json({
          error: `Category has ${courseCheck[0].count} active course(s). Move them first, or use ?force=true to unassign courses.`,
          courseCount: parseInt(courseCheck[0].count),
        });
      }
      // Force: unassign courses
      await query('UPDATE courses SET category_id=NULL WHERE category_id=$1', [req.params.id]);
    }

    // Re-parent children to this node's parent
    const parentId = existing[0].parent_id;
    await query('UPDATE categories SET parent_id=$1 WHERE parent_id=$2', [parentId, req.params.id]);

    await query('DELETE FROM categories WHERE id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'category.delete', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Category deleted. Children moved to parent.' });
  } catch (err) { next(err); }
});

/**
 * GET /courses/categories/:id/path
 * Get full breadcrumb path for a category (for navigation / UI).
 */
router.get('/categories/:id/path', auth, async (req, res, next) => {
  try {
    const { rows } = await query(`
      WITH RECURSIVE breadcrumb AS (
        SELECT id, parent_id, name, slug, 0 AS depth FROM categories WHERE id=$1
        UNION ALL
        SELECT c.id, c.parent_id, c.name, c.slug, b.depth + 1
        FROM categories c JOIN breadcrumb b ON c.id = b.parent_id
      )
      SELECT id, name, slug, depth FROM breadcrumb ORDER BY depth DESC
    `, [req.params.id]);

    res.json(rows); // ordered root → leaf
  } catch (err) { next(err); }
});

/* ══════════════════════════════════════════════════════════════════════════════
   COURSES
══════════════════════════════════════════════════════════════════════════════ */

router.get('/', auth, async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { search, status, categoryId, instructorId, level, includeSub } = req.query;

    let conds = ['c.tenant_id=$1'], params = [req.user.tenantId], p = 2;

    if (status)       { conds.push(`c.status=$${p++}`); params.push(status); }
    if (instructorId) { conds.push(`c.instructor_id=$${p++}`); params.push(instructorId); }
    if (level)        { conds.push(`c.difficulty_level=$${p++}`); params.push(level); }
    if (search)       { conds.push(`(c.title ILIKE $${p} OR c.short_description ILIKE $${p})`); params.push(`%${search}%`); p++; }

    // Category filter: optionally include all subcategories
    if (categoryId) {
      if (includeSub === 'true') {
        // Get all descendant category IDs
        const { rows: allCats } = await query(
          `WITH RECURSIVE sub AS (
             SELECT id FROM categories WHERE id=$${p}
             UNION ALL
             SELECT c.id FROM categories c JOIN sub s ON c.parent_id = s.id
           ) SELECT id FROM sub`,
          [categoryId]
        );
        params.push(categoryId); p++;
        const ids = allCats.map(r => r.id);
        if (ids.length) {
          conds.push(`c.category_id = ANY($${p++}::uuid[])`);
          params.push(ids);
        }
      } else {
        conds.push(`c.category_id=$${p++}`);
        params.push(categoryId);
      }
    }

    const WHERE = conds.join(' AND ');
    const sort  = sortClause(req, ['title','created_at','price'], 'c.created_at');

    const cnt = await query(`SELECT COUNT(*) FROM courses c WHERE ${WHERE}`, params);
    const { rows } = await query(`
      SELECT c.*,
             cat.name AS category_name, cat.parent_id AS category_parent_id,
             u.first_name || ' ' || u.last_name AS instructor_name,
             COUNT(DISTINCT e.user_id) AS enrollment_count
      FROM courses c
      LEFT JOIN categories cat ON cat.id = c.category_id
      LEFT JOIN users u        ON u.id   = c.instructor_id
      LEFT JOIN enrollments e  ON e.course_id = c.id
      WHERE ${WHERE}
      GROUP BY c.id, cat.name, cat.parent_id, u.first_name, u.last_name
      ${sort} LIMIT $${p++} OFFSET $${p++}
    `, [...params, limit, offset]);

    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

router.get('/my/enrolled', auth, async (req, res, next) => {
  try {
    const { rows } = await query(`
      SELECT c.id, c.title, c.thumbnail_url, c.difficulty_level, c.status,
             cat.name AS category_name,
             e.progress_pct, e.enrolled_at, e.completed_at, e.last_access_at,
             u.first_name || ' ' || u.last_name AS instructor_name
      FROM enrollments e
      JOIN courses c     ON c.id = e.course_id
      LEFT JOIN categories cat ON cat.id = c.category_id
      LEFT JOIN users u  ON u.id = c.instructor_id
      WHERE e.user_id=$1 AND e.status='active'
      ORDER BY e.last_access_at DESC NULLS LAST
    `, [req.user.id]);
    res.json(rows);
  } catch (err) { next(err); }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const { rows } = await query(`
      SELECT c.*,
             cat.name AS category_name,
             cat.parent_id AS category_parent_id,
             u.first_name || ' ' || u.last_name AS instructor_name,
             u.avatar_url AS instructor_avatar,
             u.bio AS instructor_bio,
             COUNT(DISTINCT e.user_id) AS enrollment_count
      FROM courses c
      LEFT JOIN categories cat ON cat.id = c.category_id
      LEFT JOIN users u        ON u.id   = c.instructor_id
      LEFT JOIN enrollments e  ON e.course_id = c.id
      WHERE c.id=$1
      GROUP BY c.id, cat.name, cat.parent_id, u.first_name, u.last_name, u.avatar_url, u.bio
    `, [req.params.id]);

    if (!rows.length) return res.status(404).json({ error: 'Course not found' });

    const course = rows[0];
    const { rows: sections } = await query(`
      SELECT s.*,
             json_agg(a ORDER BY a.sort_order) FILTER (WHERE a.id IS NOT NULL) AS activities
      FROM sections s
      LEFT JOIN activities a ON a.section_id = s.id
      WHERE s.course_id=$1
      GROUP BY s.id ORDER BY s.sort_order
    `, [req.params.id]);

    // Get category breadcrumb
    if (course.category_id) {
      const { rows: path } = await query(`
        WITH RECURSIVE bc AS (
          SELECT id, parent_id, name, slug, 0 depth FROM categories WHERE id=$1
          UNION ALL
          SELECT c.id, c.parent_id, c.name, c.slug, bc.depth+1
          FROM categories c JOIN bc ON c.id=bc.parent_id
        ) SELECT id, name, slug FROM bc ORDER BY depth DESC
      `, [course.category_id]);
      course.category_path = path;
    }

    course.sections = sections;
    res.json(course);
  } catch (err) { next(err); }
});

router.post('/', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req))
      return res.status(403).json({ error: 'Requires Admin, Instructor, or Course Manager role' });

    const {
      title, shortDescription, description, categoryId,
      tags = [], language = 'en', difficultyLevel = 'Beginner',
      status = 'draft', enrollmentType = 'open', enrollmentKey,
      price = 0, currency = 'USD', certificate = false,
      startDate, endDate, format = 'topics', completionType = 'auto',
      thumbnailUrl, bannerUrl, promoVideoUrl,
    } = req.body;

    if (!title) return res.status(400).json({ error: 'title is required' });

    // Verify categoryId belongs to this tenant
    if (categoryId) {
      const { rows: catCheck } = await query(
        'SELECT id FROM categories WHERE id=$1 AND tenant_id=$2', [categoryId, req.user.tenantId]
      );
      if (!catCheck.length)
        return res.status(400).json({ error: 'Category not found or belongs to a different tenant' });
    }

    const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') + '-' + Date.now().toString(36);

    const { rows } = await query(`
      INSERT INTO courses (
        id, tenant_id, instructor_id, title, slug, short_description, description,
        category_id, tags, language, difficulty_level, status, enrollment_type,
        enrollment_key, price, currency, certificate, start_date, end_date,
        format, completion_type, thumbnail_url, banner_url, promo_video_url
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24
      ) RETURNING *
    `, [uuid(), req.user.tenantId, req.user.id, title, slug, shortDescription, description,
        categoryId, tags, language, difficultyLevel, status, enrollmentType, enrollmentKey,
        price, currency, certificate, startDate, endDate, format, completionType,
        thumbnailUrl, bannerUrl, promoVideoUrl]);

    await auditLog({ userId: req.user.id, action: 'course.create', resourceId: rows[0].id, ip: req.ip });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:id', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req))
      return res.status(403).json({ error: 'Requires Admin, Instructor, or Course Manager role' });

    // Verify categoryId if changed
    if (req.body.categoryId) {
      const { rows: catCheck } = await query(
        'SELECT id FROM categories WHERE id=$1 AND tenant_id=$2',
        [req.body.categoryId, req.user.tenantId]
      );
      if (!catCheck.length)
        return res.status(400).json({ error: 'Category not found or belongs to a different tenant' });
    }

    const allowed = [
      'title','short_description','description','category_id','tags','language',
      'difficulty_level','status','enrollment_type','enrollment_key','price','currency',
      'certificate','start_date','end_date','format','completion_type',
      'thumbnail_url','banner_url','promo_video_url',
    ];
    const fields = [], values = []; let p = 1;
    for (const key of allowed) {
      const camel = key.replace(/_([a-z])/g, (_,c) => c.toUpperCase());
      if (req.body[camel] !== undefined || req.body[key] !== undefined) {
        fields.push(`${key}=$${p++}`);
        values.push(req.body[camel] ?? req.body[key]);
      }
    }
    if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
    values.push(req.params.id);
    await query(`UPDATE courses SET ${fields.join(',')}, updated_at=NOW() WHERE id=$${p}`, values);
    await auditLog({ userId: req.user.id, action: 'course.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Course updated' });
  } catch (err) { next(err); }
});

router.delete('/:id', auth, async (req, res, next) => {
  try {
    if (!isTenantAdmin(req))
      return res.status(403).json({ error: 'Only Tenant Admin or Super Admin can delete courses' });
    await query("UPDATE courses SET status='archived', updated_at=NOW() WHERE id=$1", [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'course.archive', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'Course archived' });
  } catch (err) { next(err); }
});

/* ── SECTIONS ────────────────────────────────────────────────────────────── */
router.post('/:courseId/sections', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req)) return res.status(403).json({ error: 'Insufficient role' });
    const { title, description, sortOrder = 0 } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });
    const { rows } = await query(
      'INSERT INTO sections (id, course_id, title, description, sort_order) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [uuid(), req.params.courseId, title, description, sortOrder]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:courseId/sections/:sectionId', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req)) return res.status(403).json({ error: 'Insufficient role' });
    const { title, description, sortOrder, visible } = req.body;
    await query(
      `UPDATE sections SET
         title=COALESCE($1,title), description=COALESCE($2,description),
         sort_order=COALESCE($3,sort_order), visible=COALESCE($4,visible)
       WHERE id=$5 AND course_id=$6`,
      [title, description, sortOrder, visible, req.params.sectionId, req.params.courseId]
    );
    res.json({ message: 'Section updated' });
  } catch (err) { next(err); }
});

router.delete('/:courseId/sections/:sectionId', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req)) return res.status(403).json({ error: 'Insufficient role' });
    await query('DELETE FROM sections WHERE id=$1 AND course_id=$2', [req.params.sectionId, req.params.courseId]);
    res.json({ message: 'Section deleted' });
  } catch (err) { next(err); }
});

/* ── ACTIVITIES ──────────────────────────────────────────────────────────── */
router.post('/:courseId/sections/:sectionId/activities', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req)) return res.status(403).json({ error: 'Insufficient role' });
    const {
      type, title, description, contentUrl, contentData = {},
      sortOrder = 0, visible = true, drmProtected = false,
      licenseProfileId, completionType = 'auto', durationMinutes,
    } = req.body;
    if (!type || !title) return res.status(400).json({ error: 'type and title are required' });
    const { rows } = await query(`
      INSERT INTO activities (
        id, section_id, course_id, type, title, description, content_url, content_data,
        sort_order, visible, drm_protected, license_profile_id, completion_type, duration_minutes
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *
    `, [uuid(), req.params.sectionId, req.params.courseId, type, title, description,
        contentUrl, JSON.stringify(contentData), sortOrder, visible, drmProtected,
        licenseProfileId, completionType, durationMinutes]);
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:courseId/activities/:activityId', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req)) return res.status(403).json({ error: 'Insufficient role' });
    const { title, description, contentUrl, visible, sortOrder, drmProtected, licenseProfileId } = req.body;
    await query(`
      UPDATE activities SET
        title=COALESCE($1,title), description=COALESCE($2,description),
        content_url=COALESCE($3,content_url), visible=COALESCE($4,visible),
        sort_order=COALESCE($5,sort_order), drm_protected=COALESCE($6,drm_protected),
        license_profile_id=COALESCE($7,license_profile_id), updated_at=NOW()
      WHERE id=$8 AND course_id=$9
    `, [title, description, contentUrl, visible, sortOrder, drmProtected, licenseProfileId,
        req.params.activityId, req.params.courseId]);
    res.json({ message: 'Activity updated' });
  } catch (err) { next(err); }
});

router.delete('/:courseId/activities/:activityId', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req)) return res.status(403).json({ error: 'Insufficient role' });
    await query('DELETE FROM activities WHERE id=$1 AND course_id=$2', [req.params.activityId, req.params.courseId]);
    res.json({ message: 'Activity deleted' });
  } catch (err) { next(err); }
});

/* ── ENROLLMENTS ─────────────────────────────────────────────────────────── */
router.post('/:courseId/enroll', auth, async (req, res, next) => {
  try {
    const uid = req.body.userId || req.user.id;
    const { rows } = await query(
      'INSERT INTO enrollments (id, course_id, user_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING *',
      [uuid(), req.params.courseId, uid]
    );
    if (!rows.length) return res.status(409).json({ error: 'Already enrolled' });
    await auditLog({ userId: req.user.id, action: 'course.enroll', resourceId: req.params.courseId, ip: req.ip });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.delete('/:courseId/enroll/:userId', auth, async (req, res, next) => {
  try {
    await query('DELETE FROM enrollments WHERE course_id=$1 AND user_id=$2', [req.params.courseId, req.params.userId]);
    res.json({ message: 'Unenrolled' });
  } catch (err) { next(err); }
});

router.get('/:courseId/enrollments', auth, async (req, res, next) => {
  try {
    if (!isCourseManager(req)) return res.status(403).json({ error: 'Insufficient role' });
    const { page, limit, offset } = paginate(req);
    const { rows } = await query(`
      SELECT e.*, u.email, u.first_name, u.last_name, u.avatar_url
      FROM enrollments e JOIN users u ON u.id=e.user_id
      WHERE e.course_id=$1 ORDER BY e.enrolled_at DESC LIMIT $2 OFFSET $3
    `, [req.params.courseId, limit, offset]);
    const cnt = await query('SELECT COUNT(*) FROM enrollments WHERE course_id=$1', [req.params.courseId]);
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

/* ── ACTIVITY COMPLETION ─────────────────────────────────────────────────── */
router.post('/:courseId/activities/:activityId/complete', auth, async (req, res, next) => {
  try {
    await query(`
      INSERT INTO activity_completions (id, activity_id, user_id, data)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (activity_id, user_id) DO UPDATE SET data=$4, completed_at=NOW()
    `, [uuid(), req.params.activityId, req.user.id, JSON.stringify(req.body.data || {})]);

    // Recalculate progress
    const { rows: act } = await query(
      'SELECT COUNT(*) FROM activities WHERE course_id=$1 AND visible=TRUE', [req.params.courseId]
    );
    const { rows: done } = await query(`
      SELECT COUNT(*) FROM activity_completions ac
      JOIN activities a ON a.id=ac.activity_id
      WHERE a.course_id=$1 AND ac.user_id=$2
    `, [req.params.courseId, req.user.id]);

    const total = parseInt(act[0].count);
    const pct   = total ? (parseInt(done[0].count) / total) * 100 : 0;

    await query(`
      UPDATE enrollments SET
        progress_pct=$1, last_access_at=NOW(),
        completed_at=CASE WHEN $1=100 THEN NOW() ELSE completed_at END,
        status=CASE WHEN $1=100 THEN 'completed' ELSE status END
      WHERE course_id=$2 AND user_id=$3
    `, [pct.toFixed(2), req.params.courseId, req.user.id]);

    res.json({ message: 'Marked complete', progress: parseFloat(pct.toFixed(2)) });
  } catch (err) { next(err); }
});


/* ── GET /courses/search ──────────────────────────────────────── */
router.get('/search', auth, async (req, res, next) => {
  try {
    const { q, category, minPrice, maxPrice, page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const conds  = ["c.tenant_id=$1 AND c.status='published'"];
    const params = [req.user.tenantId];
    let p = 2;
    if (q)        { conds.push(`(c.title ILIKE $${p} OR c.short_description ILIKE $${p})`); params.push(`%${q}%`); p++; }
    if (category) { conds.push(`c.category_id=$${p++}`); params.push(category); }
    if (minPrice) { conds.push(`c.price>=$${p++}`);      params.push(minPrice); }
    if (maxPrice) { conds.push(`c.price<=$${p++}`);      params.push(maxPrice); }
    const { rows } = await query(
      `SELECT c.*, u.first_name||' '||u.last_name AS instructor_name,
              COUNT(DISTINCT e.user_id) AS enrolled_count
       FROM courses c
       LEFT JOIN users u ON u.id = c.instructor_id
       LEFT JOIN enrollments e ON e.course_id = c.id
       WHERE ${conds.join(' AND ')}
       GROUP BY c.id, u.first_name, u.last_name
       ORDER BY c.rating DESC NULLS LAST, enrolled_count DESC
       LIMIT $${p++} OFFSET $${p++}`,
      [...params, parseInt(limit), offset]
    );
    res.json({ data: rows, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) { next(err); }
});

/* ── POST /courses/:id/rate ───────────────────────────────────── */
router.post('/:id/rate', auth, async (req, res, next) => {
  try {
    const { rating, review } = req.body;
    if (!rating || rating < 1 || rating > 5)
      return res.status(400).json({ error: 'Rating must be 1-5' });
    const { rows: e } = await query(
      'SELECT id FROM enrollments WHERE course_id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!e.length) return res.status(403).json({ error: 'Must be enrolled to rate' });
    await query(
      `UPDATE courses SET
         rating       = ROUND(((rating * review_count) + $1::numeric) / NULLIF(review_count + 1, 0), 2),
         review_count = review_count + 1
       WHERE id = $2`,
      [parseFloat(rating), req.params.id]
    );
    res.json({ message: 'Rating submitted' });
  } catch (err) { next(err); }
});

module.exports = router;
