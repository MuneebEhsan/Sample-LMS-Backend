'use strict';
const logger = require('../../../common/utils/logger');
const { query } = require('../../../db');

async function generateScheduledReport({ id, template, format, recipients, tenantId }) {
  logger.info(`[report] Generating ${template} (${format}) for tenant ${tenantId}`);
  // In production: render PDF/CSV and email to recipients
  // For now, update last_run_at
  await query('UPDATE scheduled_reports SET last_run_at=NOW() WHERE id=$1', [id]).catch(() => {});
}

module.exports = { generateScheduledReport };
