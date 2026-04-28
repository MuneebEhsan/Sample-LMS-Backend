'use strict';
const crypto = require('crypto');
const fs     = require('fs');
const { query } = require('../../db');
const logger = require('../../../common/utils/logger');

async function encryptFile({ fileId, filePath, algorithm = 'AES-256-GCM', keyId }) {
  try {
    if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);

    const fileBuffer = fs.readFileSync(filePath);
    const keyRef     = keyId || `key_${fileId}`;
    const masterKey  = Buffer.from(process.env.DRM_MASTER_KEY || '0'.repeat(64), 'hex');
    const fileKey    = crypto.createHmac('sha256', masterKey).update(keyRef).digest();

    const iv      = crypto.randomBytes(16);
    const cipher  = crypto.createCipheriv('aes-256-gcm', fileKey, iv);
    const enc     = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const encPath = filePath + '.enc';
    fs.writeFileSync(encPath, Buffer.concat([iv, authTag, enc]));

    // Persist key reference
    await query(
      `INSERT INTO encryption_keys (id, key_ref, algorithm, active)
       VALUES (gen_random_uuid(),$1,$2,TRUE) ON CONFLICT (key_ref) DO NOTHING`,
      [keyRef, algorithm]
    );

    await query(
      `UPDATE protected_files SET encrypted_path=$1, encryption_key_id=$2, status='protected', updated_at=NOW() WHERE id=$3`,
      [encPath, keyRef, fileId]
    );

    logger.info(`[DRM] File ${fileId} encrypted → ${encPath}`);
    return { encryptedPath: encPath, keyRef };
  } catch (err) {
    await query("UPDATE protected_files SET status='error' WHERE id=$1", [fileId]).catch(() => {});
    logger.error(`[DRM] Encrypt failed ${fileId}:`, err.message);
    throw err;
  }
}

module.exports = { encryptFile };
