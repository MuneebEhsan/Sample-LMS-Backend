'use strict';
const router = require('express').Router();
const { v4: uuid }     = require('uuid');
const { query }        = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../common/utils/pagination');
const { emitToUser }   = require('../../websocket');

/* ── GET /notifications ──────────────────────────────────────────────────── */
router.get('/', auth, async (req, res, next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { unreadOnly } = req.query;
    const cond = unreadOnly === 'true' ? 'AND read=FALSE' : '';
    const { rows } = await query(
      `SELECT * FROM notifications WHERE user_id=$1 ${cond} ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );
    const cnt = await query(`SELECT COUNT(*), COUNT(*) FILTER(WHERE NOT read) AS unread FROM notifications WHERE user_id=$1`, [req.user.id]);
    res.json({
      ...paginatedResponse(rows, parseInt(cnt.rows[0].count), page, limit),
      unreadCount: parseInt(cnt.rows[0].unread),
    });
  } catch (err) { next(err); }
});

/* ── PATCH /notifications/:id/read ─────────────────────────────────────── */
router.patch('/:id/read', auth, async (req, res, next) => {
  try {
    await query('UPDATE notifications SET read=TRUE WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ message: 'Marked read' });
  } catch (err) { next(err); }
});

/* ── POST /notifications/read-all ──────────────────────────────────────── */
router.post('/read-all', auth, async (req, res, next) => {
  try {
    const { rows } = await query('UPDATE notifications SET read=TRUE WHERE user_id=$1 RETURNING id', [req.user.id]);
    res.json({ message: `${rows.length} notifications marked read` });
  } catch (err) { next(err); }
});

/* ── DELETE /notifications/:id ─────────────────────────────────────────── */
router.delete('/:id', auth, async (req, res, next) => {
  try {
    await query('DELETE FROM notifications WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ message: 'Deleted' });
  } catch (err) { next(err); }
});

/* ── DELETE /notifications — clear all ─────────────────────────────────── */
router.delete('/', auth, async (req, res, next) => {
  try {
    await query('DELETE FROM notifications WHERE user_id=$1', [req.user.id]);
    res.json({ message: 'All notifications cleared' });
  } catch (err) { next(err); }
});

/* ── POST /notifications/send — admin push to user(s) ─────────────────── */
router.post('/send', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { userIds = [], type = 'info', title, body, data = {} } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });

    const sent = [];
    for (const uid of userIds) {
      const notif = await sendNotification({ userId: uid, type, title, body, data });
      sent.push(notif);
    }
    res.status(201).json({ message: `Sent to ${sent.length} users`, notifications: sent });
  } catch (err) { next(err); }
});

/* ── GET /notifications/unread-count ─────────────────────────────────── */
router.get('/unread-count', auth, async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=FALSE',
      [req.user.id]
    );
    res.json({ count: parseInt(rows[0].count) });
  } catch (err) { next(err); }
});

/* ── Internal helper: send a notification ───────────────────────────────── */
async function sendNotification({ userId, type = 'info', title, body, data = {} }) {
  const { rows } = await query(
    'INSERT INTO notifications (id, user_id, type, title, body, data) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [uuid(), userId, type, title, body, JSON.stringify(data)]
  );
  try { emitToUser(userId, 'notification:new', rows[0]); } catch {}
  return rows[0];
}

module.exports = router;
module.exports.sendNotification = sendNotification;
