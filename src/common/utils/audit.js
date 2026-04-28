'use strict';
const { v4: uuid }   = require('uuid');
const { query }      = require('../../db');
const logger         = require('./logger');

async function auditLog({ userId, tenantId, action, resource, resourceId, detail = {}, ip, userAgent }) {
  try {
    await query(`
      INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id, detail, ip_address, user_agent)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `, [uuid(), tenantId || null, userId || null, action,
        resource || null, resourceId || null,
        JSON.stringify(detail), ip || null, userAgent || null]);
  } catch (err) {
    logger.error('auditLog failed:', err.message);
  }
}

module.exports = { auditLog };
