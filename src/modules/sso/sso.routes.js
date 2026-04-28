'use strict';
const router  = require('express').Router();
const { v4: uuid }  = require('uuid');
const { query }     = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { auditLog }  = require('../../common/utils/audit');
const logger = require('../../common/utils/logger');

/* ════════════════════ SSO PROVIDERS ════════════════════════════════════════ */
router.get('/', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, name, protocol, entity_id, sso_url, active, created_at
       FROM sso_providers WHERE tenant_id=$1 ORDER BY name`,
      [req.user.tenantId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.get('/:id', auth, requireRole('Super Admin','Admin'), async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM sso_providers WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'SSO provider not found' });
    // Mask certificate
    const provider = rows[0];
    if (provider.certificate) provider.certificate = `-----BEGIN CERTIFICATE-----\n...masked...\n-----END CERTIFICATE-----`;
    res.json(provider);
  } catch (err) { next(err); }
});

router.post('/', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    const {
      name, protocol = 'saml2',
      entityId, ssoUrl, sloUrl, certificate,
      attributeMap = { email: 'email', firstName: 'givenName', lastName: 'sn' },
    } = req.body;
    const { rows } = await query(
      `INSERT INTO sso_providers (id, tenant_id, name, protocol, entity_id, sso_url, slo_url, certificate, attribute_map)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, name, protocol, active`,
      [uuid(), req.user.tenantId, name, protocol, entityId, ssoUrl, sloUrl, certificate, JSON.stringify(attributeMap)]
    );
    await auditLog({ userId: req.user.id, action: 'sso.provider.create', resourceId: rows[0].id, ip: req.ip });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:id', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    const { name, entityId, ssoUrl, sloUrl, certificate, attributeMap, active } = req.body;
    await query(
      `UPDATE sso_providers SET
         name=COALESCE($1,name), entity_id=COALESCE($2,entity_id),
         sso_url=COALESCE($3,sso_url), slo_url=COALESCE($4,slo_url),
         certificate=COALESCE($5,certificate), attribute_map=COALESCE($6,attribute_map),
         active=COALESCE($7,active)
       WHERE id=$8`,
      [name, entityId, ssoUrl, sloUrl, certificate,
       attributeMap ? JSON.stringify(attributeMap) : null, active, req.params.id]
    );
    await auditLog({ userId: req.user.id, action: 'sso.provider.update', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'SSO provider updated' });
  } catch (err) { next(err); }
});

router.delete('/:id', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    await query('DELETE FROM sso_providers WHERE id=$1', [req.params.id]);
    await auditLog({ userId: req.user.id, action: 'sso.provider.delete', resourceId: req.params.id, ip: req.ip });
    res.json({ message: 'SSO provider deleted' });
  } catch (err) { next(err); }
});

/* ─── Toggle active ─────────────────────────────────────────────────────── */
router.patch('/:id/toggle', auth, requireRole('Super Admin'), async (req, res, next) => {
  try {
    await query('UPDATE sso_providers SET active=NOT active WHERE id=$1', [req.params.id]);
    const { rows } = await query('SELECT active FROM sso_providers WHERE id=$1', [req.params.id]);
    res.json({ active: rows[0]?.active });
  } catch (err) { next(err); }
});

/* ════════════════════ SAML 2.0 LOGIN FLOW ═══════════════════════════════════ */

/**
 * GET /sso/:providerId/init — initiate SAML SSO (redirect to IdP)
 */
router.get('/:providerId/init', async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT * FROM sso_providers WHERE id=$1 AND active=TRUE', [req.params.providerId]
    );
    if (!rows.length) return res.status(404).json({ error: 'SSO provider not found or inactive' });

    const provider = rows[0];
    if (provider.protocol === 'saml2' || provider.protocol === 'saml') {
      // Build SAML AuthnRequest
      const authnRequest = buildSamlAuthnRequest(provider);
      const redirectUrl  = `${provider.sso_url}?SAMLRequest=${encodeURIComponent(authnRequest)}`;
      res.redirect(redirectUrl);
    } else if (provider.protocol === 'oauth2') {
      res.redirect(`${provider.sso_url}?client_id=${provider.entity_id}&response_type=code&scope=openid+email+profile`);
    } else {
      res.status(400).json({ error: `Unsupported protocol: ${provider.protocol}` });
    }
  } catch (err) { next(err); }
});

/**
 * POST /sso/:providerId/callback — SAML assertion consumer service
 */
router.post('/:providerId/callback', async (req, res, next) => {
  try {
    const { SAMLResponse } = req.body;
    if (!SAMLResponse) return res.status(400).json({ error: 'No SAML response received' });

    const { rows } = await query(
      'SELECT * FROM sso_providers WHERE id=$1 AND active=TRUE', [req.params.providerId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Provider not found' });

    const provider = rows[0];

    // Parse SAML response (production: use passport-saml or samlify)
    const userData = await parseSamlResponse(SAMLResponse, provider);
    if (!userData) return res.status(401).json({ error: 'Invalid SAML assertion' });

    const attrMap = provider.attribute_map || {};
    const email   = userData[attrMap.email || 'email'];
    if (!email) return res.status(400).json({ error: 'Email attribute missing from SAML assertion' });

    // Find or create user
    const { rows: existing } = await query(
      'SELECT * FROM users WHERE email=$1 AND tenant_id=$2', [email, provider.tenant_id]
    );

    let user;
    if (existing.length) {
      user = existing[0];
    } else {
      const { rows: newUser } = await query(
        `INSERT INTO users (id, tenant_id, email, first_name, last_name, status, email_verified)
         VALUES ($1,$2,$3,$4,$5,'active',TRUE) RETURNING *`,
        [uuid(), provider.tenant_id, email,
         userData[attrMap.firstName || 'givenName'] || '',
         userData[attrMap.lastName  || 'sn']        || '']
      );
      user = newUser[0];
      // Assign Student role by default
      const { rows: roleRows } = await query("SELECT id FROM roles WHERE name='Student' LIMIT 1");
      if (roleRows.length) await query('INSERT INTO user_roles VALUES ($1,$2)', [user.id, roleRows[0].id]);
    }

    // Issue JWT
    const jwt    = require('jsonwebtoken');
    const access = jwt.sign(
      { sub: user.id, tid: user.tenant_id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    const refresh = jwt.sign(
      { sub: user.id, tid: user.tenant_id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d' }
    );

    // Store SSO session
    await query(
      `INSERT INTO sso_sessions (id, user_id, provider_id, name_id, expires_at)
       VALUES ($1,$2,$3,$4, NOW()+INTERVAL '8 hours')`,
      [uuid(), user.id, provider.id, userData.nameId || email]
    );

    await auditLog({ userId: user.id, action: 'auth.sso.login', detail: { provider: provider.name }, ip: req.ip });

    // Redirect to frontend with tokens
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.redirect(`${frontendUrl}/sso/callback?access=${access}&refresh=${refresh}`);
  } catch (err) { next(err); }
});

/* ─── GET /sso/:providerId/metadata — SAML SP metadata ─────────────────── */
router.get('/:providerId/metadata', async (req, res, next) => {
  try {
    const acsUrl  = `${process.env.API_BASE_URL || 'http://localhost:4000'}/api/v1/sso/${req.params.providerId}/callback`;
    const spEntityId = process.env.SAML_ISSUER || 'acadlms';
    const metadata = `<?xml version="1.0"?>
<EntityDescriptor entityID="${spEntityId}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="false" WantAssertionsSigned="true">
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsUrl}" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`;
    res.type('application/xml').send(metadata);
  } catch (err) { next(err); }
});

/* ─── Helpers ────────────────────────────────────────────────────────────── */
function buildSamlAuthnRequest(provider) {
  const id       = '_' + uuid().replace(/-/g, '');
  const issueInstant = new Date().toISOString();
  const acsUrl   = `${process.env.API_BASE_URL || 'http://localhost:4000'}/api/v1/sso/${provider.id}/callback`;
  const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="${id}" Version="2.0" IssueInstant="${issueInstant}"
    AssertionConsumerServiceURL="${acsUrl}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${process.env.SAML_ISSUER || 'acadlms'}</saml:Issuer>
</samlp:AuthnRequest>`;
  return Buffer.from(xml).toString('base64');
}

async function parseSamlResponse(samlResponseB64, provider) {
  try {
    const xml  = Buffer.from(samlResponseB64, 'base64').toString('utf-8');
    // Production: validate XML signature with provider certificate
    // Stub: extract email from NameID or Attribute
    const emailMatch = xml.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
    if (emailMatch) return { email: emailMatch[1], nameId: emailMatch[1] };
    const attrMatch = xml.match(/<AttributeValue[^>]*>([^<@\s]+@[^<\s]+)<\/AttributeValue>/);
    if (attrMatch) return { email: attrMatch[1] };
    return null;
  } catch {
    return null;
  }
}

module.exports = router;
