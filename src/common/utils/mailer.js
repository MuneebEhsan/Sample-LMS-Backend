'use strict';
const nodemailer = require('nodemailer');
const logger     = require('./logger');

let transporter;

function getTransporter() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host:   process.env.SMTP_HOST || 'smtp.mailtrap.io',
      port:   Number(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  return transporter;
}

async function sendEmail({ to, subject, html, text }) {
  if (!process.env.SMTP_USER) {
    logger.warn(`[mailer] SMTP not configured — skipping email to ${to}: ${subject}`);
    return;
  }
  try {
    const info = await getTransporter().sendMail({
      from: `"${process.env.EMAIL_FROM_NAME || 'AcadLMS'}" <${process.env.EMAIL_FROM || 'noreply@acadlms.com'}>`,
      to, subject, html, text,
    });
    logger.info(`[mailer] Email sent to ${to}: ${info.messageId}`);
    return info;
  } catch (err) {
    logger.error(`[mailer] Failed to send email to ${to}:`, err.message);
    throw err;
  }
}

// Template helpers
function emailVerificationTemplate(name, url) {
  return {
    subject: 'Verify your AcadLMS email',
    html: `<h2>Hello ${name},</h2><p>Click below to verify your email:</p><a href="${url}" style="background:#F59E0B;color:#000;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold">Verify Email</a><p>Link expires in 24 hours.</p>`,
  };
}

function passwordResetTemplate(name, url) {
  return {
    subject: 'Reset your AcadLMS password',
    html: `<h2>Hello ${name},</h2><p>Click below to reset your password:</p><a href="${url}" style="background:#EF4444;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold">Reset Password</a><p>Link expires in 1 hour. If you did not request this, ignore this email.</p>`,
  };
}

function welcomeTenantAdminTemplate(name, tenantName, email, password, url) {
  return {
    subject: `Welcome to AcadLMS — Your ${tenantName} admin account`,
    html: `<h2>Welcome, ${name}!</h2><p>Your admin account for <strong>${tenantName}</strong> has been created.</p><table><tr><td><strong>Email:</strong></td><td>${email}</td></tr><tr><td><strong>Password:</strong></td><td>${password}</td></tr></table><br/><a href="${url}" style="background:#F59E0B;color:#000;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold">Login Now</a><p>Please change your password after first login.</p>`,
  };
}

module.exports = { sendEmail, emailVerificationTemplate, passwordResetTemplate, welcomeTenantAdminTemplate };
