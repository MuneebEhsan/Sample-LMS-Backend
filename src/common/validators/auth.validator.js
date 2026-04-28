'use strict';
const { body, validationResult } = require('express-validator');

const rules = {
  register: [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 8 }).withMessage('Password min 8 characters'),
    body('firstName').optional().isString().trim(),
    body('lastName').optional().isString().trim(),
  ],
  login: [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  changePassword: [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 8 }),
  ],
  resetPassword: [
    body('token').notEmpty(),
    body('newPassword').isLength({ min: 8 }),
  ],
};

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ error: 'Validation failed', details: errors.array() });
  }
  next();
}

module.exports = { rules, validate };
