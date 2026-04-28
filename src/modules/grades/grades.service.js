'use strict';
const { query } = require('../../db');
const logger    = require('../../common/utils/logger');

async function recalculateGrades({ courseId, userId }) {
  logger.info(`[grades] Recalculating for course=${courseId} user=${userId || 'all'}`);
  try {
    const userCond = userId ? 'AND g.user_id=$2' : '';
    const params   = userId ? [courseId, userId] : [courseId];
    const { rows } = await query(`
      SELECT gi.id AS item_id, gi.weight, gi.max_grade, g.user_id, g.raw_grade
      FROM grade_items gi
      JOIN grades g ON g.grade_item_id = gi.id
      WHERE gi.course_id=$1 ${userCond}
    `, params);

    // Group by user
    const byUser = {};
    for (const r of rows) {
      if (!byUser[r.user_id]) byUser[r.user_id] = [];
      byUser[r.user_id].push(r);
    }

    for (const [uid, items] of Object.entries(byUser)) {
      const totalWeight = items.reduce((s, i) => s + parseFloat(i.weight || 1), 0);
      if (totalWeight === 0) continue;
      const weighted = items.reduce((s, i) =>
        s + (parseFloat(i.raw_grade || 0) / parseFloat(i.max_grade || 100)) * parseFloat(i.weight || 1), 0);
      const final = (weighted / totalWeight) * 100;

      await query(`
        UPDATE grades SET final_grade=$1, updated_at=NOW()
        WHERE grade_item_id IN (SELECT id FROM grade_items WHERE course_id=$2) AND user_id=$3
      `, [final.toFixed(2), courseId, uid]);
    }
    logger.info(`[grades] Recalculated ${Object.keys(byUser).length} users for course ${courseId}`);
  } catch (err) {
    logger.error('[grades] Recalculate failed:', err.message);
  }
}

module.exports = { recalculateGrades };
