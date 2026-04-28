'use strict';
const router  = require('express').Router();
const { v4: uuid } = require('uuid');
const { query, transaction } = require('../../db');
const { auth, requireRole }  = require('../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../common/utils/pagination');
const { auditLog }  = require('../../common/utils/audit');
const { enqueueGrade } = require('../../jobs');

/* ════════════════════ GRADE CATEGORIES ══════════════════════════════════════ */
router.get('/categories', auth, async (req, res, next) => {
  try {
    const { courseId } = req.query;
    if (!courseId) return res.status(400).json({ error: 'courseId required' });
    const { rows } = await query(
      `SELECT * FROM grade_categories WHERE course_id=$1 ORDER BY name`, [courseId]
    );
    // Build hierarchy
    const map  = Object.fromEntries(rows.map(r => [r.id, { ...r, children: [] }]));
    const tree = [];
    for (const r of rows) {
      if (r.parent_id && map[r.parent_id]) map[r.parent_id].children.push(map[r.id]);
      else tree.push(map[r.id]);
    }
    res.json(tree);
  } catch (err) { next(err); }
});

router.post('/categories', auth, requireRole('Super Admin','Admin','Instructor'), async (req, res, next) => {
  try {
    const { courseId, name, aggregation = 'weighted_mean', weight = 1.0, parentId, dropLowest = 0 } = req.body;
    const { rows } = await query(
      `INSERT INTO grade_categories (id, course_id, parent_id, name, aggregation, weight, drop_lowest)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [uuid(), courseId, parentId, name, aggregation, weight, dropLowest]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/categories/:id', auth, async (req, res, next) => {
  try {
    const { name, aggregation, weight, dropLowest } = req.body;
    await query(
      `UPDATE grade_categories SET
         name=COALESCE($1,name), aggregation=COALESCE($2,aggregation),
         weight=COALESCE($3,weight), drop_lowest=COALESCE($4,drop_lowest)
       WHERE id=$5`,
      [name, aggregation, weight, dropLowest, req.params.id]
    );
    res.json({ message: 'Category updated' });
  } catch (err) { next(err); }
});

/* ════════════════════ GRADE ITEMS ═══════════════════════════════════════════ */
router.get('/items', auth, async (req, res, next) => {
  try {
    const { courseId } = req.query;
    if (!courseId) return res.status(400).json({ error: 'courseId required' });
    const { rows } = await query(
      `SELECT gi.*, gc.name AS category_name
       FROM grade_items gi
       LEFT JOIN grade_categories gc ON gc.id = gi.grade_category_id
       WHERE gi.course_id=$1 ORDER BY gi.name`, [courseId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/items', auth, requireRole('Super Admin','Admin','Instructor'), async (req, res, next) => {
  try {
    const {
      courseId, gradeCategoryId, activityId, name,
      type = 'manual', maxGrade = 100, passGrade = 50,
      weight = 1.0, extraCredit = false, hidden = false, hiddenUntil,
    } = req.body;
    const { rows } = await query(
      `INSERT INTO grade_items (id, course_id, grade_category_id, activity_id, name,
         type, max_grade, pass_grade, weight, extra_credit, hidden, hidden_until)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [uuid(), courseId, gradeCategoryId, activityId, name,
       type, maxGrade, passGrade, weight, extraCredit, hidden, hiddenUntil]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/items/:id', auth, async (req, res, next) => {
  try {
    const { name, maxGrade, passGrade, weight, hidden, hiddenUntil, extraCredit } = req.body;
    await query(
      `UPDATE grade_items SET
         name=COALESCE($1,name), max_grade=COALESCE($2,max_grade),
         pass_grade=COALESCE($3,pass_grade), weight=COALESCE($4,weight),
         hidden=COALESCE($5,hidden), hidden_until=COALESCE($6,hidden_until),
         extra_credit=COALESCE($7,extra_credit)
       WHERE id=$8`,
      [name, maxGrade, passGrade, weight, hidden, hiddenUntil, extraCredit, req.params.id]
    );
    res.json({ message: 'Grade item updated' });
  } catch (err) { next(err); }
});

/* ════════════════════ GRADES (the actual marks) ═════════════════════════════ */
/**
 * GET /grades/grader?courseId=xxx  — full spreadsheet-style gradebook
 */
router.get('/grader', auth, async (req, res, next) => {
  try {
    const { courseId } = req.query;
    if (!courseId) return res.status(400).json({ error: 'courseId required' });

    // Grade items
    const { rows: items } = await query(
      'SELECT * FROM grade_items WHERE course_id=$1 ORDER BY name', [courseId]
    );

    // Enrolled students
    const { rows: students } = await query(
      `SELECT u.id, u.first_name, u.last_name, u.email, u.avatar_url
       FROM enrollments e JOIN users u ON u.id = e.user_id
       WHERE e.course_id=$1 AND e.status='active'
       ORDER BY u.last_name, u.first_name`, [courseId]
    );

    // All grades for this course
    const { rows: gradeRows } = await query(
      `SELECT g.* FROM grades g
       JOIN grade_items gi ON gi.id = g.grade_item_id
       WHERE gi.course_id=$1`, [courseId]
    );
    const gradeMap = {};
    for (const g of gradeRows) {
      if (!gradeMap[g.user_id]) gradeMap[g.user_id] = {};
      gradeMap[g.user_id][g.grade_item_id] = g;
    }

    const rows = students.map(s => ({
      student:    s,
      grades:     Object.fromEntries(items.map(i => [i.id, gradeMap[s.id]?.[i.id] || null])),
      average:    computeAverage(items, gradeMap[s.id] || {}),
    }));

    res.json({ items, rows });
  } catch (err) { next(err); }
});

function computeAverage(items, gradeMap) {
  let totalWeight = 0, weightedSum = 0;
  for (const item of items) {
    const g = gradeMap[item.id];
    if (g?.final_grade != null) {
      const pct = (g.final_grade / item.max_grade) * 100;
      weightedSum  += pct * item.weight;
      totalWeight  += item.weight;
    }
  }
  return totalWeight ? (weightedSum / totalWeight).toFixed(2) : null;
}

/* ─── PUT /grades/:gradeItemId/users/:userId — enter/update a grade ─────── */
router.put('/:gradeItemId/users/:userId', auth, requireRole('Super Admin','Admin','Instructor','Teaching Assistant'), async (req, res, next) => {
  try {
    const { rawGrade, feedback } = req.body;

    // Fetch existing grade for history
    const { rows: existing } = await query(
      'SELECT * FROM grades WHERE grade_item_id=$1 AND user_id=$2',
      [req.params.gradeItemId, req.params.userId]
    );
    const oldGrade = existing[0]?.final_grade ?? null;

    const { rows } = await query(
      `INSERT INTO grades (id, grade_item_id, user_id, raw_grade, final_grade, feedback, graded_by, graded_at)
       VALUES ($1,$2,$3,$4,$4,$5,$6, NOW())
       ON CONFLICT (grade_item_id, user_id)
       DO UPDATE SET raw_grade=$4, final_grade=$4, feedback=$5, graded_by=$6, updated_at=NOW()
       RETURNING *`,
      [uuid(), req.params.gradeItemId, req.params.userId, rawGrade, feedback, req.user.id]
    );

    // Grade history
    await query(
      `INSERT INTO grade_history (id, grade_id, grade_item_id, user_id, old_grade, new_grade, changed_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [uuid(), rows[0].id, req.params.gradeItemId, req.params.userId, oldGrade, rawGrade, req.user.id]
    );

    // Async grade recalculation
    await enqueueGrade({ courseId: null, gradeItemId: req.params.gradeItemId, userId: req.params.userId });
    await auditLog({ userId: req.user.id, action: 'grade.update', resourceId: req.params.gradeItemId, ip: req.ip });

    res.json(rows[0]);
  } catch (err) { next(err); }
});

/* ─── Bulk grade update ──────────────────────────────────────────────────── */
router.post('/bulk', auth, requireRole('Super Admin','Admin','Instructor'), async (req, res, next) => {
  try {
    const { grades } = req.body; // [{ gradeItemId, userId, rawGrade, feedback }]
    await transaction(async (client) => {
      for (const g of grades) {
        await client.query(
          `INSERT INTO grades (id, grade_item_id, user_id, raw_grade, final_grade, feedback, graded_by)
           VALUES ($1,$2,$3,$4,$4,$5,$6)
           ON CONFLICT (grade_item_id, user_id)
           DO UPDATE SET raw_grade=$4, final_grade=$4, feedback=$5, graded_by=$6, updated_at=NOW()`,
          [uuid(), g.gradeItemId, g.userId, g.rawGrade, g.feedback, req.user.id]
        );
      }
    });
    res.json({ message: `${grades.length} grades saved` });
  } catch (err) { next(err); }
});

/* ════════════════════ GRADE HISTORY ═════════════════════════════════════════ */
router.get('/history', auth, async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { userId, gradeItemId, courseId, from, to } = req.query;

    let conds = ['1=1'], params = [], p = 1;
    if (userId)      { conds.push(`gh.user_id=$${p++}`);       params.push(userId); }
    if (gradeItemId) { conds.push(`gh.grade_item_id=$${p++}`); params.push(gradeItemId); }
    if (courseId)    { conds.push(`gi.course_id=$${p++}`);     params.push(courseId); }
    if (from)        { conds.push(`gh.changed_at>=$${p++}`);   params.push(from); }
    if (to)          { conds.push(`gh.changed_at<=$${p++}`);   params.push(to); }

    const WHERE = conds.join(' AND ');
    const { rows } = await query(
      `SELECT gh.*,
              gi.name AS item_name,
              u.first_name || ' ' || u.last_name AS student_name,
              cb.first_name || ' ' || cb.last_name AS changed_by_name
       FROM grade_history gh
       JOIN grade_items gi ON gi.id = gh.grade_item_id
       JOIN users u         ON u.id = gh.user_id
       LEFT JOIN users cb   ON cb.id = gh.changed_by
       WHERE ${WHERE}
       ORDER BY gh.changed_at DESC LIMIT $${p++} OFFSET $${p++}`,
      [...params, limit, offset]
    );
    const cnt = await query(`SELECT COUNT(*) FROM grade_history gh JOIN grade_items gi ON gi.id=gh.grade_item_id WHERE ${WHERE}`, params);
    res.json(paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit));
  } catch (err) { next(err); }
});

/* ════════════════════ OVERVIEW REPORT ═══════════════════════════════════════ */
router.get('/overview', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT c.id, c.title, c.thumbnail_url,
              COUNT(DISTINCT e.user_id) AS enrolled,
              COUNT(DISTINCT CASE WHEN e.completed_at IS NOT NULL THEN e.user_id END) AS completed,
              AVG(e.progress_pct) AS avg_progress,
              ROUND(AVG(g.final_grade),2) AS avg_grade
       FROM courses c
       LEFT JOIN enrollments e ON e.course_id = c.id
       LEFT JOIN grade_items gi ON gi.course_id = c.id
       LEFT JOIN grades g ON g.grade_item_id = gi.id
       WHERE c.tenant_id=$1
       GROUP BY c.id ORDER BY c.title`,
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

/* ════════════════════ USER REPORT (student report card) ═════════════════════ */
router.get('/user-report', auth, async (req, res, next) => {
  try {
    const uid = req.query.userId || req.user.id;
    const { rows } = await query(
      `SELECT c.id AS course_id, c.title,
              gi.id AS item_id, gi.name AS item_name, gi.max_grade,
              g.final_grade, g.feedback, g.graded_at,
              e.progress_pct, e.completed_at
       FROM enrollments e
       JOIN courses c ON c.id = e.course_id
       LEFT JOIN grade_items gi ON gi.course_id = c.id
       LEFT JOIN grades g ON g.grade_item_id = gi.id AND g.user_id = e.user_id
       WHERE e.user_id=$1 AND e.status='active'
       ORDER BY c.title, gi.name`, [uid]
    );
    // Group by course
    const map = {};
    for (const r of rows) {
      if (!map[r.course_id]) map[r.course_id] = { course_id: r.course_id, title: r.title, progress_pct: r.progress_pct, completed_at: r.completed_at, items: [] };
      if (r.item_id) map[r.course_id].items.push({ id: r.item_id, name: r.item_name, maxGrade: r.max_grade, finalGrade: r.final_grade, feedback: r.feedback, gradedAt: r.graded_at });
    }
    res.json(Object.values(map));
  } catch (err) { next(err); }
});

/* ════════════════════ GRADE SCALES ═════════════════════════════════════════ */
router.get('/scales', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT * FROM grade_scales WHERE tenant_id=$1 OR course_id IS NOT NULL ORDER BY name',
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/scales', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { name, description, items, courseId } = req.body;
    const { rows } = await query(
      `INSERT INTO grade_scales (id, tenant_id, course_id, name, description, items)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [uuid(), req.user.tenantId, courseId, name, description, JSON.stringify(items)]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

/* ════════════════════ GENERAL SETTINGS ═════════════════════════════════════ */
router.get('/settings', auth, async (req, res, next) => {
  try {
    const { rows } = await query('SELECT settings FROM courses WHERE id=$1', [req.query.courseId]);
    res.json(rows[0]?.settings || {});
  } catch (err) { next(err); }
});

router.patch('/settings', auth, requireRole('Super Admin','Admin','Instructor'), async (req, res, next) => {
  try {
    await query('UPDATE courses SET settings=$1, updated_at=NOW() WHERE id=$2',
      [JSON.stringify(req.body), req.query.courseId]);
    res.json({ message: 'Settings saved' });
  } catch (err) { next(err); }
});

/* Grades service for background recalculation */
async function recalculateGrades({ gradeItemId, userId }) {
  // Re-fetch and store final grade (stub — real impl would apply curves/aggregation)
  const { rows } = await query('SELECT raw_grade FROM grades WHERE grade_item_id=$1 AND user_id=$2', [gradeItemId, userId]);
  if (rows.length) {
    await query('UPDATE grades SET final_grade=$1, updated_at=NOW() WHERE grade_item_id=$2 AND user_id=$3',
      [rows[0].raw_grade, gradeItemId, userId]);
  }
}

module.exports = router;
module.exports.recalculateGrades = recalculateGrades;
