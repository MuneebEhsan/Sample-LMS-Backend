'use strict';
require('dotenv').config();
const app      = require('./app');
const http     = require('http');
const { initDB }     = require('./db');
const { initRedis }  = require('./config/redis');
const { initSocket } = require('./websocket');
const { initQueues } = require('./jobs');
const logger         = require('./common/utils/logger');

const PORT = process.env.PORT || 4000;

async function bootstrap() {
  try {
    // 1. Database
    await initDB();
    logger.info('✅  PostgreSQL connected');

    // 2. Redis
    await initRedis();
    logger.info('✅  Redis connected');

    // 3. HTTP server + Socket.IO
    const server = http.createServer(app);
    initSocket(server);
    logger.info('✅  WebSocket (Socket.IO) initialised');

    // 4. Background job queues
    initQueues();
    logger.info('✅  BullMQ queues initialised');

    // 5. Listen
    server.listen(PORT, () => {
      logger.info(`🚀  AcadLMS API running on http://localhost:${PORT}`);
      logger.info(`📖  Swagger UI: http://localhost:${PORT}/api-docs`);
    });

    // Graceful shutdown
    const shutdown = (sig) => {
      logger.info(`${sig} received — shutting down gracefully`);
      server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
      });
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));
  } catch (err) {
    logger.error('Bootstrap failed:', err);
    process.exit(1);
  }
}

bootstrap();
