/**
 * Super Admin Setup Script
 * Run this on the VPS to create/fix the initial super admin account.
 */
const { query } = require('../src/db');
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');
require('dotenv').config();

async function setup() {
  console.log('🚀 Starting Super Admin setup...');

  try {
    // 1. Ensure 'main' tenant exists
    const { rows: tenantRows } = await query(
      "INSERT INTO tenants (id, name, slug) VALUES ($1, 'Main Academy', 'main') ON CONFLICT (slug) DO UPDATE SET name = 'Main Academy' RETURNING id",
      [uuid()]
    );
    const tenantId = tenantRows[0].id;
    console.log(`✅ Tenant 'main' ready (ID: ${tenantId})`);

    // 2. Ensure 'Super Admin' role exists
    const { rows: roleRows } = await query(
      "INSERT INTO roles (id, tenant_id, name, description) VALUES ($1, $2, 'Super Admin', 'Full system access') ON CONFLICT (name) DO UPDATE SET description = 'Full system access' RETURNING id",
      [uuid(), tenantId]
    );
    const roleId = roleRows[0].id;
    console.log(`✅ Role 'Super Admin' ready (ID: ${roleId})`);

    // 3. Create/Update the Admin User
    const email = 'admin@taleem.life';
    const password = 'admin123';
    const hash = await bcrypt.hash(password, 12);

    const { rows: userRows } = await query(
      `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, status)
       VALUES ($1, $2, $3, $4, 'Super', 'Admin', 'active')
       ON CONFLICT (email) DO UPDATE SET password_hash = $4, status = 'active'
       RETURNING id`,
      [uuid(), tenantId, email, hash]
    );
    const userId = userRows[0].id;
    console.log(`✅ User '${email}' ready (ID: ${userId})`);

    // 4. Link User to Role
    await query(
      "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [userId, roleId]
    );
    console.log(`✅ User linked to Super Admin role`);

    console.log('\n✨ SETUP COMPLETE! ✨');
    console.log('---------------------------');
    console.log(`Email:    ${email}`);
    console.log(`Password: ${password}`);
    console.log('---------------------------');
    console.log('You can now log in at https://www.taleem.life');

  } catch (err) {
    console.error('❌ Setup failed:', err.message);
  } finally {
    process.exit();
  }
}

setup();
