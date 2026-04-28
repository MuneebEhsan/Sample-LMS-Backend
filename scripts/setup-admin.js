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
    let roleId;
    const { rows: existingRoles } = await query("SELECT id FROM roles WHERE name = 'Super Admin' LIMIT 1");
    if (existingRoles.length > 0) {
      roleId = existingRoles[0].id;
      console.log(`✅ Role 'Super Admin' found (ID: ${roleId})`);
    } else {
      roleId = uuid();
      await query(
        "INSERT INTO roles (id, tenant_id, name, description) VALUES ($1, $2, 'Super Admin', 'Full system access')",
        [roleId, tenantId]
      );
      console.log(`✅ Role 'Super Admin' created (ID: ${roleId})`);
    }

    // 3. Create/Update the Admin User
    const email = 'admin@taleem.life';
    const password = 'admin123';
    const hash = await bcrypt.hash(password, 12);
    let userId;

    const { rows: existingUsers } = await query("SELECT id FROM users WHERE email = $1 LIMIT 1", [email]);
    if (existingUsers.length > 0) {
      userId = existingUsers[0].id;
      await query("UPDATE users SET password_hash = $1, status = 'active', tenant_id = $2 WHERE id = $3", [hash, tenantId, userId]);
      console.log(`✅ User '${email}' updated (ID: ${userId})`);
    } else {
      userId = uuid();
      await query(
        `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, status)
         VALUES ($1, $2, $3, $4, 'Super', 'Admin', 'active')`,
        [userId, tenantId, email, hash]
      );
      console.log(`✅ User '${email}' created (ID: ${userId})`);
    }

    // 4. Link User to Role
    const { rows: urCheck } = await query("SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2", [userId, roleId]);
    if (urCheck.length === 0) {
      await query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)", [userId, roleId]);
    }
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
