'use strict';
// ══════════════════════════════════════════════════════════════════════════════
// PHASE 4 — Messaging Module
// GET    /messaging/conversations            — list my conversations
// POST   /messaging/conversations            — start new conversation
// GET    /messaging/conversations/:id        — get conversation + messages
// POST   /messaging/conversations/:id/messages — send message
// PUT    /messaging/messages/:id             — edit message
// DELETE /messaging/messages/:id             — delete message
// POST   /messaging/conversations/:id/read   — mark as read
// POST   /messaging/conversations/:id/mute   — mute/unmute
// GET    /messaging/unread                   — unread count
// ══════════════════════════════════════════════════════════════════════════════
const router       = require('express').Router();
const { v4: uuid } = require('uuid');
const { query }    = require('../../db');
const { auth }     = require('../../common/middleware/auth');
const { paginate } = require('../../common/utils/pagination');
const { emitToUser } = require('../../websocket');

router.use(auth);

// ── GET /messaging/conversations ───────────────────────────────────────────────
router.get('/conversations', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT c.id, c.type, c.course_id, c.created_at,
              cm.last_read_at, cm.muted,
              -- Last message
              (SELECT json_build_object('body', m.body, 'sender_id', m.sender_id, 'created_at', m.created_at)
               FROM messages m WHERE m.conversation_id = c.id AND m.deleted_at IS NULL
               ORDER BY m.created_at DESC LIMIT 1) AS last_message,
              -- Unread count
              (SELECT COUNT(*) FROM messages m
               WHERE m.conversation_id = c.id AND m.deleted_at IS NULL
               AND (cm.last_read_at IS NULL OR m.created_at > cm.last_read_at)) AS unread_count,
              -- Members info
              json_agg(json_build_object('id', u.id, 'first_name', u.first_name, 'last_name', u.last_name, 'avatar_url', u.avatar_url))
                FILTER (WHERE u.id != $1) AS participants
       FROM conversations c
       JOIN conversation_members cm  ON cm.conversation_id = c.id AND cm.user_id = $1
       JOIN conversation_members cm2 ON cm2.conversation_id = c.id
       JOIN users u ON u.id = cm2.user_id
       GROUP BY c.id, cm.last_read_at, cm.muted
       ORDER BY (SELECT created_at FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) DESC NULLS LAST`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// ── POST /messaging/conversations ─────────────────────────────────────────────
router.post('/conversations', async (req, res, next) => {
  try {
    const { participantIds = [], type = 'direct', courseId, initialMessage } = req.body;
    const allMembers = [...new Set([req.user.id, ...participantIds])];
    if (allMembers.length < 2) return res.status(400).json({ error: 'At least 2 participants required' });

    // Check for existing direct conversation between same 2 users
    if (type === 'direct' && allMembers.length === 2) {
      const { rows: existing } = await query(
        `SELECT c.id FROM conversations c
         JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = $1
         JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = $2
         WHERE c.type='direct'`, [allMembers[0], allMembers[1]]
      );
      if (existing.length) return res.json({ id: existing[0].id, existing: true });
    }

    const convId = uuid();
    await query(
      `INSERT INTO conversations (id, tenant_id, type, course_id) VALUES ($1,$2,$3,$4)`,
      [convId, req.user.tenantId, type, courseId || null]
    );
    for (const uid of allMembers) {
      await query(
        'INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [convId, uid]
      );
    }

    if (initialMessage) {
      const msgId = uuid();
      await query(
        'INSERT INTO messages (id, conversation_id, sender_id, body) VALUES ($1,$2,$3,$4)',
        [msgId, convId, req.user.id, initialMessage]
      );
      // Notify participants
      for (const uid of participantIds) {
        try { emitToUser(uid, 'message:new', { conversationId: convId, body: initialMessage, senderId: req.user.id }); } catch {}
      }
    }
    res.status(201).json({ id: convId });
  } catch (err) { next(err); }
});

// ── GET /messaging/conversations/:id ──────────────────────────────────────────
router.get('/conversations/:id', async (req, res, next) => {
  try {
    // Verify membership
    const { rows: member } = await query(
      'SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!member.length) return res.status(403).json({ error: 'Not a member of this conversation' });

    const { limit, offset } = paginate(req);
    const [conv, messages] = await Promise.all([
      query(`SELECT c.*, json_agg(json_build_object('id', u.id, 'first_name', u.first_name, 'last_name', u.last_name, 'avatar_url', u.avatar_url, 'muted', cm.muted))
             AS members FROM conversations c
             JOIN conversation_members cm ON cm.conversation_id = c.id
             JOIN users u ON u.id = cm.user_id WHERE c.id=$1 GROUP BY c.id`, [req.params.id]),
      query(`SELECT m.*, u.first_name, u.last_name, u.avatar_url
             FROM messages m JOIN users u ON u.id = m.sender_id
             WHERE m.conversation_id=$1 AND m.deleted_at IS NULL
             ORDER BY m.created_at DESC LIMIT $2 OFFSET $3`, [req.params.id, limit, offset]),
    ]);
    if (!conv.rows.length) return res.status(404).json({ error: 'Conversation not found' });
    res.json({ ...conv.rows[0], messages: messages.rows.reverse() });
  } catch (err) { next(err); }
});

// ── POST /messaging/conversations/:id/messages ────────────────────────────────
router.post('/conversations/:id/messages', async (req, res, next) => {
  try {
    const { body, attachmentUrl } = req.body;
    if (!body && !attachmentUrl) return res.status(400).json({ error: 'body or attachment required' });

    const { rows: member } = await query(
      'SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!member.length) return res.status(403).json({ error: 'Not a member' });

    const msgId = uuid();
    const { rows } = await query(
      `INSERT INTO messages (id, conversation_id, sender_id, body, attachment_url)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [msgId, req.params.id, req.user.id, body || null, attachmentUrl || null]
    );

    // Broadcast to all members except sender
    const { rows: members } = await query(
      'SELECT user_id FROM conversation_members WHERE conversation_id=$1 AND user_id!=$2',
      [req.params.id, req.user.id]
    );
    const payload = { ...rows[0], conversationId: req.params.id };
    for (const m of members) {
      try { emitToUser(m.user_id, 'message:new', payload); } catch {}
    }

    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// ── PUT /messaging/messages/:id ────────────────────────────────────────────────
router.put('/messages/:id', async (req, res, next) => {
  try {
    const { body } = req.body;
    const { rows } = await query(
      `UPDATE messages SET body=$1 WHERE id=$2 AND sender_id=$3 AND deleted_at IS NULL RETURNING *`,
      [body, req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Message not found or not yours' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// ── DELETE /messaging/messages/:id ────────────────────────────────────────────
router.delete('/messages/:id', async (req, res, next) => {
  try {
    await query(
      `UPDATE messages SET deleted_at=NOW() WHERE id=$1 AND sender_id=$2`,
      [req.params.id, req.user.id]
    );
    res.json({ message: 'Message deleted' });
  } catch (err) { next(err); }
});

// ── POST /messaging/conversations/:id/read ────────────────────────────────────
router.post('/conversations/:id/read', async (req, res, next) => {
  try {
    await query(
      `UPDATE conversation_members SET last_read_at=NOW()
       WHERE conversation_id=$1 AND user_id=$2`, [req.params.id, req.user.id]
    );
    res.json({ message: 'Marked as read' });
  } catch (err) { next(err); }
});

// ── POST /messaging/conversations/:id/mute ────────────────────────────────────
router.post('/conversations/:id/mute', async (req, res, next) => {
  try {
    const { muted } = req.body;
    await query(
      `UPDATE conversation_members SET muted=$1 WHERE conversation_id=$2 AND user_id=$3`,
      [muted, req.params.id, req.user.id]
    );
    res.json({ muted });
  } catch (err) { next(err); }
});

// ── GET /messaging/unread ──────────────────────────────────────────────────────
router.get('/unread', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT COUNT(m.id)::int AS total
       FROM messages m
       JOIN conversation_members cm ON cm.conversation_id = m.conversation_id AND cm.user_id = $1
       WHERE m.deleted_at IS NULL AND m.sender_id != $1
       AND (cm.last_read_at IS NULL OR m.created_at > cm.last_read_at)`,
      [req.user.id]
    );
    res.json({ unread: rows[0].total });
  } catch (err) { next(err); }
});

module.exports = router;
