'use strict';
const fs     = require('fs');
const logger = require('../../common/utils/logger');
const { query } = require('../../db');

async function processScormPackage({ packageId, filePath, version }) {
  logger.info(`[SCORM] Processing ${packageId} (v${version})`);
  try {
    let manifest = {};
    if (filePath && fs.existsSync(filePath)) {
      // Try to read imsmanifest.xml from ZIP
      try {
        const AdmZip = require('adm-zip');
        const zip = new AdmZip(filePath);
        const raw = zip.readAsText('imsmanifest.xml');
        if (raw) manifest = { raw: raw.substring(0, 500) };
      } catch {}
    }
    await query(
      "UPDATE scorm_packages SET status='active', manifest=$1 WHERE id=$2",
      [JSON.stringify(manifest), packageId]
    );
    logger.info(`[SCORM] Package ${packageId} activated`);
  } catch (err) {
    logger.error(`[SCORM] Failed ${packageId}:`, err.message);
    await query("UPDATE scorm_packages SET status='error' WHERE id=$1", [packageId]).catch(() => {});
  }
}

module.exports = { processScormPackage };
