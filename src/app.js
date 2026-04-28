'use strict';
const express        = require('express');
const cors           = require('cors');
const helmet         = require('helmet');
const morgan         = require('morgan');
const compression    = require('compression');
const rateLimit      = require('express-rate-limit');
const swaggerUi      = require('swagger-ui-express');
const swaggerSpec    = require('./config/swagger');
const logger         = require('./common/utils/logger');
const { errorHandler } = require('./common/middleware/errorHandler');

// ── Route imports ─────────────────────────────────────────────────────────────
const authRoutes           = require('./modules/auth/auth.routes');
const userRoutes           = require('./modules/users/users.routes');
const courseRoutes         = require('./modules/courses/courses.routes');
const gradeRoutes          = require('./modules/grades/grades.routes');
const paymentRoutes        = require('./modules/payments/payments.routes');
const messagingRoutes      = require('./modules/messaging/messaging.routes');
const notificationRoutes   = require('./modules/notifications/notifications.routes');
const securityRoutes       = require('./modules/security/security.routes');
const drmLicenseRoutes     = require('./modules/drm/licenses/licenses.routes');
const drmEncryptRoutes     = require('./modules/drm/encryption/encryption.routes');
const drmTokenRoutes       = require('./modules/drm/tokens/tokens.routes');
const drmStorageRoutes     = require('./modules/drm/storage/storage.routes');
const drmViolationRoutes   = require('./modules/drm/violations/violations.routes');
const drmReportRoutes      = require('./modules/drm/reports/reports.routes');
const multitenancyRoutes   = require('./modules/multitenancy/multitenancy.routes');
const scormRoutes          = require('./modules/scorm/scorm.routes');
const ssoRoutes            = require('./modules/sso/sso.routes');
const advancedDrmRoutes    = require('./modules/drm/advanced/advanced-drm.routes');

const app = express();

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:', 'blob:'],
    },
  },
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(cors({
  origin:      process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods:     ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Tenant-ID','X-Request-ID'],
}));

// ── Request parsing ───────────────────────────────────────────────────────────
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ── HTTP logging ──────────────────────────────────────────────────────────────
app.use(morgan('combined', {
  stream: { write: (msg) => logger.http(msg.trim()) },
}));

// ── Global rate limiter ───────────────────────────────────────────────────────
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please try again later.' },
}));

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({
  status: 'ok',
  service: 'acadlms-api',
  version: '1.0.0',
  timestamp: new Date().toISOString(),
}));

// ── Swagger / OpenAPI ─────────────────────────────────────────────────────────
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customSiteTitle: 'AcadLMS API',
  customCss: '.swagger-ui .topbar { background: #05070C; }',
}));

// ── API Routes ────────────────────────────────────────────────────────────────
const API = process.env.API_PREFIX || '/api/v1';

app.use(`${API}/auth`,          authRoutes);
app.use(`${API}/users`,         userRoutes);
app.use(`${API}/courses`,       courseRoutes);
app.use(`${API}/grades`,        gradeRoutes);
app.use(`${API}/payments`,      paymentRoutes);
app.use(`${API}/messaging`,     messagingRoutes);
app.use(`${API}/notifications`, notificationRoutes);
app.use(`${API}/security`,      securityRoutes);
app.use(`${API}/drm/licenses`,  drmLicenseRoutes);
app.use(`${API}/drm/encrypt`,   drmEncryptRoutes);
app.use(`${API}/drm/tokens`,    drmTokenRoutes);
app.use(`${API}/drm/storage`,   drmStorageRoutes);
app.use(`${API}/drm/violations`,drmViolationRoutes);
app.use(`${API}/drm/reports`,   drmReportRoutes);
app.use(`${API}/tenants`,       multitenancyRoutes);
app.use(`${API}/scorm`,         scormRoutes);
app.use(`${API}/sso`,           ssoRoutes);
app.use(`${API}/drm/advanced`,  advancedDrmRoutes);

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

// ── Global error handler ──────────────────────────────────────────────────────
app.use(errorHandler);

module.exports = app;
