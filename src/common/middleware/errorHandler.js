'use strict';
const logger = require('../utils/logger');

function errorHandler(err, req, res, _next) {
  // Postgres unique violation
  if (err.code === '23505') {
    return res.status(409).json({ error: 'Duplicate entry — resource already exists' });
  }
  // Postgres foreign key violation
  if (err.code === '23503') {
    return res.status(400).json({ error: 'Related resource not found' });
  }
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired' });
  }
  // Multer file size limit
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large' });
  }
  // Validation errors (express-validator)
  if (err.type === 'validation') {
    return res.status(422).json({ error: 'Validation failed', details: err.errors });
  }

  const statusCode = err.status || err.statusCode || 500;
  if (statusCode >= 500) {
    logger.error(`[${req.method}] ${req.path} — ${err.message}`, { stack: err.stack });
  }

  res.status(statusCode).json({
    error:   err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' ? { stack: err.stack } : {}),
  });
}

module.exports = { errorHandler };
