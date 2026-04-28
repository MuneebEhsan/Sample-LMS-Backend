'use strict';
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title:       'AcadLMS + DRM Platform API',
      version:     '2.0.0',
      description: 'Full-stack multi-tenant LMS with enterprise DRM — 10 phases, 17 modules',
      contact:     { name: 'AcadLMS Team', email: 'api@acadlms.com' },
    },
    servers: [
      { url: 'http://localhost:4000/api/v1', description: 'Development' },
      { url: 'https://api.yourdomain.com/api/v1', description: 'Production' },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http', scheme: 'bearer', bearerFormat: 'JWT',
        },
      },
    },
    security: [{ bearerAuth: [] }],
    tags: [
      { name: 'Auth',           description: 'Authentication & sessions' },
      { name: 'Users',          description: 'User management' },
      { name: 'Courses',        description: 'Courses & activities' },
      { name: 'Grades',         description: 'Gradebook & reports' },
      { name: 'Payments',       description: 'Payments & revenue' },
      { name: 'Messaging',      description: 'Real-time messaging' },
      { name: 'Notifications',  description: 'In-app notifications' },
      { name: 'Security',       description: 'Security & audit' },
      { name: 'DRM',            description: 'Digital rights management' },
      { name: 'Multi-tenancy',  description: 'Tenant management' },
      { name: 'SCORM',          description: 'SCORM/H5P content' },
      { name: 'SSO',            description: 'Single sign-on' },
    ],
  },
  apis: ['./src/modules/**/*.routes.js'],
};

module.exports = swaggerJsdoc(options);
