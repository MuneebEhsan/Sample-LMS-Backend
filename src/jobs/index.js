'use strict';
const { Queue, Worker } = require('bullmq');
const { getRedis }      = require('../config/redis');
const logger            = require('../common/utils/logger');

let queues = {};

const QUEUE_NAMES = {
  ENCRYPT:  'drm:encrypt',
  EMAIL:    'email',
  REPORT:   'report',
  SCORM:    'scorm:process',
  GRADE:    'grade:recalculate',
};

function initQueues() {
  const connection = getRedis();

  Object.values(QUEUE_NAMES).forEach(name => {
    queues[name] = new Queue(name, { connection });
  });

  // ── DRM Encryption Worker ──────────────────────────────────────────────
  new Worker(QUEUE_NAMES.ENCRYPT, async (job) => {
    const { encryptFile } = require('../modules/drm/encryption/encryption.service');
    await encryptFile(job.data);
    logger.info(`[encrypt:worker] Completed job ${job.id}`);
  }, { connection, concurrency: 4 });

  // ── Email Worker ───────────────────────────────────────────────────────
  new Worker(QUEUE_NAMES.EMAIL, async (job) => {
    const { sendEmail } = require('../common/utils/mailer');
    await sendEmail(job.data);
    logger.info(`[email:worker] Sent email to ${job.data.to}`);
  }, { connection, concurrency: 10 });

  // ── Report Worker ──────────────────────────────────────────────────────
  new Worker(QUEUE_NAMES.REPORT, async (job) => {
    const { generateScheduledReport } = require('../modules/drm/reports/reports.service');
    await generateScheduledReport(job.data);
    logger.info(`[report:worker] Generated report ${job.id}`);
  }, { connection, concurrency: 2 });

  // ── SCORM Processing Worker ───────────────────────────────────────────
  new Worker(QUEUE_NAMES.SCORM, async (job) => {
    const { processScormPackage } = require('../modules/scorm/scorm.service');
    await processScormPackage(job.data);
    logger.info(`[scorm:worker] Processed package ${job.data.packageId}`);
  }, { connection, concurrency: 2 });

  // ── Grade Recalculation Worker ─────────────────────────────────────────
  new Worker(QUEUE_NAMES.GRADE, async (job) => {
    const { recalculateGrades } = require('../modules/grades/grades.service');
    await recalculateGrades(job.data);
    logger.info(`[grade:worker] Recalculated grades for course ${job.data.courseId}`);
  }, { connection, concurrency: 3 });

  logger.info('✅  BullMQ workers started');
}

async function enqueueEncrypt(data)  { return queues[QUEUE_NAMES.ENCRYPT]?.add('encrypt', data, { attempts: 3, backoff: { type: 'exponential', delay: 2000 } }); }
async function enqueueEmail(data)    { return queues[QUEUE_NAMES.EMAIL]?.add('email', data, { attempts: 5 }); }
async function enqueueReport(data)   { return queues[QUEUE_NAMES.REPORT]?.add('report', data, { attempts: 2 }); }
async function enqueueScorm(data)    { return queues[QUEUE_NAMES.SCORM]?.add('scorm', data, { attempts: 3 }); }
async function enqueueGradeCalc(data){ return queues[QUEUE_NAMES.GRADE]?.add('grade', data, { attempts: 3 }); }

module.exports = { initQueues, enqueueEncrypt, enqueueEmail, enqueueReport, enqueueScorm, enqueueGradeCalc };
