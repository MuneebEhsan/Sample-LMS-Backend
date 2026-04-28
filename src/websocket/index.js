'use strict';
const { Server } = require('socket.io');
const jwt        = require('jsonwebtoken');
const logger     = require('../common/utils/logger');

let io;
const userSockets = new Map(); // userId → Set of socket IDs

function initSocket(server) {
  io = new Server(server, {
    cors: {
      origin:      process.env.FRONTEND_URL || 'http://localhost:5173',
      credentials: true,
    },
    transports: ['websocket', 'polling'],
  });

  // Auth middleware
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token ||
                    socket.handshake.headers?.authorization?.replace('Bearer ', '');
      if (!token) return next(new Error('Authentication required'));
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId   = payload.sub;
      socket.tenantId = payload.tid;
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    const { userId, tenantId } = socket;
    logger.debug(`WS connect: user=${userId} socket=${socket.id}`);

    // Track socket
    if (!userSockets.has(userId)) userSockets.set(userId, new Set());
    userSockets.get(userId).add(socket.id);

    // Join tenant room for broadcasts
    socket.join(`tenant:${tenantId}`);
    socket.join(`user:${userId}`);

    // Conversation rooms
    socket.on('join:conversation', (convId) => {
      socket.join(`conv:${convId}`);
    });
    socket.on('leave:conversation', (convId) => {
      socket.leave(`conv:${convId}`);
    });

    socket.on('disconnect', () => {
      userSockets.get(userId)?.delete(socket.id);
      if (userSockets.get(userId)?.size === 0) userSockets.delete(userId);
      logger.debug(`WS disconnect: user=${userId}`);
    });
  });

  logger.info('✅  Socket.IO initialised');
  return io;
}

// Emit to a specific user (all their sockets)
function emitToUser(userId, event, data) {
  if (!io) return;
  io.to(`user:${userId}`).emit(event, data);
}

// Emit to all users in a tenant
function emitToTenant(tenantId, event, data) {
  if (!io) return;
  io.to(`tenant:${tenantId}`).emit(event, data);
}

// Emit to a conversation room
function emitToConversation(convId, event, data) {
  if (!io) return;
  io.to(`conv:${convId}`).emit(event, data);
}

// Emit DRM event to tenant
function emitDRMEvent(tenantId, data) {
  emitToTenant(tenantId, 'drm:event', data);
}

// Emit live audit log entry to admins in a tenant
function emitAuditEntry(tenantId, entry) {
  emitToTenant(tenantId, 'log:entry', entry);
}

function getIO() { return io; }

module.exports = { initSocket, emitToUser, emitToTenant, emitToConversation, emitDRMEvent, emitAuditEntry, getIO };
