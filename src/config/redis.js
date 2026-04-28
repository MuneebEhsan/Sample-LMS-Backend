'use strict';
const Redis  = require('ioredis');
const logger = require('../common/utils/logger');

let client;

function getRedis() {
  if (!client) {
    client = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => Math.min(times * 200, 3000),
      lazyConnect: true,
    });
    client.on('error', (err) => logger.error('Redis error:', err.message));
    client.on('connect', () => logger.info('Redis connected'));
  }
  return client;
}

async function initRedis() {
  const redis = getRedis();
  await redis.connect().catch(() => {}); // already connected = no-op
  return redis;
}

// Cache helpers
async function cacheGet(key) {
  try {
    const val = await getRedis().get(key);
    return val ? JSON.parse(val) : null;
  } catch { return null; }
}

async function cacheSet(key, value, ttlSeconds = 300) {
  try {
    await getRedis().setex(key, ttlSeconds, JSON.stringify(value));
  } catch {}
}

async function cacheDel(key) {
  try { await getRedis().del(key); } catch {}
}

async function cacheDelPattern(pattern) {
  try {
    const keys = await getRedis().keys(pattern);
    if (keys.length) await getRedis().del(...keys);
  } catch {}
}

module.exports = { getRedis, initRedis, cacheGet, cacheSet, cacheDel, cacheDelPattern };
