'use strict';
const { Pool } = require('pg');
const logger   = require('../common/utils/logger');

let pool;

// ── Connection pool ───────────────────────────────────────────────────────────
function getPool() {
  if (!pool) {
    pool = new Pool({
      host:     process.env.DB_HOST || 'localhost',
      port:     Number(process.env.DB_PORT) || 5432,
      database: process.env.DB_NAME || 'acadlms',
      user:     process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD,
      min:      Number(process.env.DB_POOL_MIN) || 2,
      max:      Number(process.env.DB_POOL_MAX) || 20,
      ssl:      process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });
    pool.on('error', (err) => logger.error('PG pool error:', err));
  }
  return pool;
}

// ── Generic query helper ──────────────────────────────────────────────────────
async function query(sql, params = []) {
  const client = await getPool().connect();
  try {
    const result = await client.query(sql, params);
    return result;
  } finally {
    client.release();
  }
}

// ── Transaction helper ────────────────────────────────────────────────────────
async function transaction(fn) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── Init (called at bootstrap) ────────────────────────────────────────────────
async function initDB() {
  const p = getPool();
  const client = await p.connect();
  client.release();           // just test connectivity
  await runMigrations();
}

// ── Schema migrations ─────────────────────────────────────────────────────────
async function runMigrations() {
  const SCHEMA = `
    /* ── Extensions ── */
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 1 — Auth & Users
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS tenants (
      id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      name          TEXT NOT NULL,
      slug          TEXT UNIQUE NOT NULL,
      plan          TEXT NOT NULL DEFAULT 'Starter',
      color         TEXT DEFAULT '#6366F1',
      logo_url      TEXT,
      subdomain     TEXT UNIQUE,
      custom_domain TEXT,
      status        TEXT NOT NULL DEFAULT 'active',
      settings      JSONB DEFAULT '{}',
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
      email           TEXT NOT NULL,
      password_hash   TEXT,
      first_name      TEXT,
      last_name       TEXT,
      avatar_url      TEXT,
      bio             TEXT,
      timezone        TEXT DEFAULT 'UTC',
      language        TEXT DEFAULT 'en',
      status          TEXT NOT NULL DEFAULT 'active',
      email_verified  BOOLEAN DEFAULT FALSE,
      two_fa_secret   TEXT,
      two_fa_enabled  BOOLEAN DEFAULT FALSE,
      google_id       TEXT,
      microsoft_id    TEXT,
      last_login_at   TIMESTAMPTZ,
      last_login_ip   TEXT,
      failed_logins   INT DEFAULT 0,
      locked_until    TIMESTAMPTZ,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(tenant_id, email)
    );
    CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    CREATE TABLE IF NOT EXISTS roles (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      description TEXT,
      permissions JSONB DEFAULT '{}',
      is_system   BOOLEAN DEFAULT FALSE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_roles (
      user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
      role_id    UUID REFERENCES roles(id) ON DELETE CASCADE,
      context    TEXT,
      PRIMARY KEY (user_id, role_id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
      token_hash    TEXT NOT NULL,
      refresh_token TEXT,
      ip_address    TEXT,
      user_agent    TEXT,
      expires_at    TIMESTAMPTZ NOT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);

    CREATE TABLE IF NOT EXISTS email_verifications (
      id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
      token      TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
      token      TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 2 — Courses
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS categories (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
      parent_id   UUID REFERENCES categories(id),
      name        TEXT NOT NULL,
      slug        TEXT NOT NULL,
      description TEXT,
      icon_url    TEXT,
      sort_order  INT DEFAULT 0,
      visibility  TEXT DEFAULT 'public',
      metadata    JSONB DEFAULT '{}',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS courses (
      id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id         UUID REFERENCES tenants(id) ON DELETE CASCADE,
      category_id       UUID REFERENCES categories(id),
      instructor_id     UUID REFERENCES users(id),
      title             TEXT NOT NULL,
      slug              TEXT,
      short_description TEXT,
      description       TEXT,
      thumbnail_url     TEXT,
      banner_url        TEXT,
      promo_video_url   TEXT,
      language          TEXT DEFAULT 'en',
      difficulty_level  TEXT DEFAULT 'Beginner',
      status            TEXT DEFAULT 'draft',
      enrollment_type   TEXT DEFAULT 'open',
      enrollment_key    TEXT,
      price             DECIMAL(10,2) DEFAULT 0,
      currency          TEXT DEFAULT 'USD',
      certificate       BOOLEAN DEFAULT FALSE,
      start_date        DATE,
      end_date          DATE,
      enroll_open_date  DATE,
      enroll_close_date DATE,
      format            TEXT DEFAULT 'topics',
      completion_type   TEXT DEFAULT 'auto',
      settings          JSONB DEFAULT '{}',
      tags              TEXT[] DEFAULT '{}',
      created_at        TIMESTAMPTZ DEFAULT NOW(),
      updated_at        TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_courses_tenant ON courses(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_courses_instructor ON courses(instructor_id);
    CREATE INDEX IF NOT EXISTS idx_courses_status ON courses(status);

    CREATE TABLE IF NOT EXISTS sections (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      course_id   UUID REFERENCES courses(id) ON DELETE CASCADE,
      title       TEXT NOT NULL,
      description TEXT,
      sort_order  INT DEFAULT 0,
      visible     BOOLEAN DEFAULT TRUE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activities (
      id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      section_id      UUID REFERENCES sections(id) ON DELETE CASCADE,
      course_id       UUID REFERENCES courses(id) ON DELETE CASCADE,
      type            TEXT NOT NULL,
      title           TEXT NOT NULL,
      description     TEXT,
      content_url     TEXT,
      content_data    JSONB DEFAULT '{}',
      sort_order      INT DEFAULT 0,
      visible         BOOLEAN DEFAULT TRUE,
      drm_protected   BOOLEAN DEFAULT FALSE,
      license_profile_id UUID,
      completion_type TEXT DEFAULT 'auto',
      duration_minutes INT,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_activities_section ON activities(section_id);
    CREATE INDEX IF NOT EXISTS idx_activities_course  ON activities(course_id);

    CREATE TABLE IF NOT EXISTS enrollments (
      id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      course_id      UUID REFERENCES courses(id) ON DELETE CASCADE,
      user_id        UUID REFERENCES users(id)   ON DELETE CASCADE,
      status         TEXT DEFAULT 'active',
      enrolled_at    TIMESTAMPTZ DEFAULT NOW(),
      completed_at   TIMESTAMPTZ,
      progress_pct   DECIMAL(5,2) DEFAULT 0,
      last_access_at TIMESTAMPTZ,
      UNIQUE(course_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_enrollments_user   ON enrollments(user_id);
    CREATE INDEX IF NOT EXISTS idx_enrollments_course ON enrollments(course_id);

    CREATE TABLE IF NOT EXISTS activity_completions (
      id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      activity_id  UUID REFERENCES activities(id) ON DELETE CASCADE,
      user_id      UUID REFERENCES users(id)      ON DELETE CASCADE,
      completed_at TIMESTAMPTZ DEFAULT NOW(),
      data         JSONB DEFAULT '{}',
      UNIQUE(activity_id, user_id)
    );

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 3 — Grades
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS grade_categories (
      id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      course_id       UUID REFERENCES courses(id) ON DELETE CASCADE,
      parent_id       UUID REFERENCES grade_categories(id),
      name            TEXT NOT NULL,
      aggregation     TEXT DEFAULT 'weighted_mean',
      weight          DECIMAL(5,2) DEFAULT 1.0,
      drop_lowest     INT DEFAULT 0,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS grade_items (
      id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      course_id           UUID REFERENCES courses(id) ON DELETE CASCADE,
      grade_category_id   UUID REFERENCES grade_categories(id),
      activity_id         UUID REFERENCES activities(id),
      name                TEXT NOT NULL,
      type                TEXT DEFAULT 'manual',
      max_grade           DECIMAL(10,2) DEFAULT 100,
      pass_grade          DECIMAL(10,2) DEFAULT 50,
      weight              DECIMAL(5,2) DEFAULT 1.0,
      extra_credit        BOOLEAN DEFAULT FALSE,
      hidden              BOOLEAN DEFAULT FALSE,
      hidden_until        TIMESTAMPTZ,
      created_at          TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS grades (
      id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      grade_item_id UUID REFERENCES grade_items(id) ON DELETE CASCADE,
      user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
      raw_grade     DECIMAL(10,2),
      final_grade   DECIMAL(10,2),
      feedback      TEXT,
      graded_by     UUID REFERENCES users(id),
      graded_at     TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(grade_item_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS grade_history (
      id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      grade_id      UUID REFERENCES grades(id),
      grade_item_id UUID REFERENCES grade_items(id),
      user_id       UUID REFERENCES users(id),
      old_grade     DECIMAL(10,2),
      new_grade     DECIMAL(10,2),
      changed_by    UUID REFERENCES users(id),
      reason        TEXT,
      changed_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_grade_history_user ON grade_history(user_id);

    CREATE TABLE IF NOT EXISTS grade_scales (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id),
      course_id   UUID REFERENCES courses(id),
      name        TEXT NOT NULL,
      description TEXT,
      items       JSONB NOT NULL DEFAULT '[]',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 4 — Payments & Messaging
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS coupons (
      id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id      UUID REFERENCES tenants(id),
      code           TEXT NOT NULL,
      type           TEXT DEFAULT 'percentage',
      value          DECIMAL(10,2) NOT NULL,
      usage_limit    INT,
      used_count     INT DEFAULT 0,
      expires_at     TIMESTAMPTZ,
      applicable_to  JSONB DEFAULT '{}',
      active         BOOLEAN DEFAULT TRUE,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orders (
      id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id         UUID REFERENCES users(id),
      course_id       UUID REFERENCES courses(id),
      tenant_id       UUID REFERENCES tenants(id),
      coupon_id       UUID REFERENCES coupons(id),
      amount          DECIMAL(10,2) NOT NULL,
      currency        TEXT DEFAULT 'USD',
      gateway         TEXT,
      gateway_order_id TEXT,
      status          TEXT DEFAULT 'pending',
      invoice_url     TEXT,
      refunded_at     TIMESTAMPTZ,
      refund_amount   DECIMAL(10,2),
      metadata        JSONB DEFAULT '{}',
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_orders_user    ON orders(user_id);
    CREATE INDEX IF NOT EXISTS idx_orders_course  ON orders(course_id);
    CREATE INDEX IF NOT EXISTS idx_orders_status  ON orders(status);

    CREATE TABLE IF NOT EXISTS conversations (
      id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id    UUID REFERENCES tenants(id),
      type         TEXT DEFAULT 'direct',
      course_id    UUID REFERENCES courses(id),
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS conversation_members (
      conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
      user_id         UUID REFERENCES users(id)          ON DELETE CASCADE,
      role            TEXT DEFAULT 'member',
      muted           BOOLEAN DEFAULT FALSE,
      last_read_at    TIMESTAMPTZ,
      PRIMARY KEY (conversation_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id       UUID REFERENCES users(id),
      body            TEXT,
      attachment_url  TEXT,
      deleted_at      TIMESTAMPTZ,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id);

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 5 — Security & Appearance
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS audit_logs (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id),
      user_id     UUID REFERENCES users(id),
      action      TEXT NOT NULL,
      resource    TEXT,
      resource_id TEXT,
      detail      JSONB DEFAULT '{}',
      ip_address  TEXT,
      user_agent  TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user   ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

    CREATE TABLE IF NOT EXISTS ip_rules (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id),
      type        TEXT NOT NULL,
      cidr        TEXT NOT NULL,
      reason      TEXT,
      active      BOOLEAN DEFAULT TRUE,
      created_by  UUID REFERENCES users(id),
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS appearance (
      id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id       UUID REFERENCES tenants(id) UNIQUE,
      primary_color   TEXT DEFAULT '#F59E0B',
      secondary_color TEXT DEFAULT '#6366F1',
      accent_color    TEXT DEFAULT '#14B8A6',
      font_family     TEXT DEFAULT 'Plus Jakarta Sans',
      logo_url        TEXT,
      favicon_url     TEXT,
      login_bg_url    TEXT,
      custom_css      TEXT,
      custom_js       TEXT,
      dark_mode       BOOLEAN DEFAULT TRUE,
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
      type        TEXT NOT NULL,
      title       TEXT NOT NULL,
      body        TEXT,
      data        JSONB DEFAULT '{}',
      read        BOOLEAN DEFAULT FALSE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id);

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 6 — DRM Core
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS drm_groups (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      description TEXT,
      color       TEXT DEFAULT '#F59E0B',
      auto_rule   JSONB DEFAULT '{}',
      active      BOOLEAN DEFAULT TRUE,
      expires_at  TIMESTAMPTZ,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS drm_group_members (
      group_id   UUID REFERENCES drm_groups(id) ON DELETE CASCADE,
      user_id    UUID REFERENCES users(id)       ON DELETE CASCADE,
      added_at   TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (group_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS license_profiles (
      id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id         UUID REFERENCES tenants(id) ON DELETE CASCADE,
      name              TEXT NOT NULL,
      description       TEXT,
      color             TEXT DEFAULT '#F59E0B',
      tier              TEXT DEFAULT 'standard',
      max_devices       INT DEFAULT 3,
      max_streams       INT DEFAULT 2,
      downloads_allowed BOOLEAN DEFAULT FALSE,
      offline_allowed   BOOLEAN DEFAULT FALSE,
      offline_ttl_hours INT DEFAULT 24,
      watermark_enabled BOOLEAN DEFAULT TRUE,
      screen_block      BOOLEAN DEFAULT TRUE,
      geo_enabled       BOOLEAN DEFAULT FALSE,
      geo_countries     TEXT[] DEFAULT '{}',
      window_start      TIME DEFAULT '00:00',
      window_end        TIME DEFAULT '23:59',
      expiry_days       INT,
      max_plays         INT,
      token_ttl_seconds INT DEFAULT 3600,
      encryption_alg    TEXT DEFAULT 'AES-256-GCM',
      created_at        TIMESTAMPTZ DEFAULT NOW(),
      updated_at        TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS drm_group_profiles (
      group_id           UUID REFERENCES drm_groups(id)       ON DELETE CASCADE,
      license_profile_id UUID REFERENCES license_profiles(id) ON DELETE CASCADE,
      PRIMARY KEY (group_id, license_profile_id)
    );

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 7 — Rights & Cloud Storage
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS protected_files (
      id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id          UUID REFERENCES tenants(id) ON DELETE CASCADE,
      course_id          UUID REFERENCES courses(id),
      activity_id        UUID REFERENCES activities(id),
      original_name      TEXT NOT NULL,
      mime_type          TEXT NOT NULL,
      file_size_bytes    BIGINT,
      storage_provider   TEXT NOT NULL,
      storage_path       TEXT NOT NULL,
      encrypted_path     TEXT,
      encryption_alg     TEXT DEFAULT 'AES-256-GCM',
      encryption_key_id  TEXT,
      license_profile_id UUID REFERENCES license_profiles(id),
      access_count       INT DEFAULT 0,
      last_accessed_at   TIMESTAMPTZ,
      status             TEXT DEFAULT 'protected',
      created_at         TIMESTAMPTZ DEFAULT NOW(),
      updated_at         TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_pf_tenant  ON protected_files(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_pf_course  ON protected_files(course_id);

    CREATE TABLE IF NOT EXISTS file_rights (
      id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      file_id            UUID REFERENCES protected_files(id) ON DELETE CASCADE,
      subject_type       TEXT NOT NULL,
      subject_id         UUID NOT NULL,
      license_profile_id UUID REFERENCES license_profiles(id),
      expires_at         TIMESTAMPTZ,
      created_by         UUID REFERENCES users(id),
      created_at         TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_fr_file    ON file_rights(file_id);
    CREATE INDEX IF NOT EXISTS idx_fr_subject ON file_rights(subject_type, subject_id);

    CREATE TABLE IF NOT EXISTS storage_providers (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      type        TEXT NOT NULL,
      config      JSONB NOT NULL DEFAULT '{}',
      is_default  BOOLEAN DEFAULT FALSE,
      active      BOOLEAN DEFAULT TRUE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS encryption_keys (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id),
      key_ref     TEXT NOT NULL UNIQUE,
      algorithm   TEXT DEFAULT 'AES-256-GCM',
      rotated_at  TIMESTAMPTZ,
      active      BOOLEAN DEFAULT TRUE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 8 — Token Delivery & Watermark
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS drm_tokens (
      id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      file_id      UUID REFERENCES protected_files(id) ON DELETE CASCADE,
      user_id      UUID REFERENCES users(id),
      token_hash   TEXT NOT NULL UNIQUE,
      ip_address   TEXT,
      user_agent   TEXT,
      device_id    TEXT,
      expires_at   TIMESTAMPTZ NOT NULL,
      used_at      TIMESTAMPTZ,
      revoked      BOOLEAN DEFAULT FALSE,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_tokens_user ON drm_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_tokens_file ON drm_tokens(file_id);
    CREATE INDEX IF NOT EXISTS idx_tokens_hash ON drm_tokens(token_hash);

    CREATE TABLE IF NOT EXISTS user_devices (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
      device_id   TEXT NOT NULL,
      device_name TEXT,
      device_type TEXT,
      last_seen   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, device_id)
    );

    CREATE TABLE IF NOT EXISTS watermark_templates (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id),
      name        TEXT NOT NULL,
      template    TEXT NOT NULL,
      position    TEXT DEFAULT 'diagonal',
      opacity     DECIMAL(3,2) DEFAULT 0.3,
      font_size   INT DEFAULT 14,
      color       TEXT DEFAULT 'rgba(255,255,255,0.5)',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 9 — Reports, Violations, Performance
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS drm_violations (
      id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id        UUID REFERENCES tenants(id),
      user_id          UUID REFERENCES users(id),
      file_id          UUID REFERENCES protected_files(id),
      violation_type   TEXT NOT NULL,
      severity         TEXT DEFAULT 'medium',
      ip_address       TEXT,
      user_agent       TEXT,
      detail           JSONB DEFAULT '{}',
      action_taken     TEXT,
      resolved         BOOLEAN DEFAULT FALSE,
      resolved_by      UUID REFERENCES users(id),
      resolved_at      TIMESTAMPTZ,
      created_at       TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_viol_tenant ON drm_violations(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_viol_user   ON drm_violations(user_id);
    CREATE INDEX IF NOT EXISTS idx_viol_type   ON drm_violations(violation_type);

    CREATE TABLE IF NOT EXISTS alert_rules (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id),
      name        TEXT NOT NULL,
      condition   JSONB NOT NULL,
      action      JSONB NOT NULL,
      severity    TEXT DEFAULT 'medium',
      active      BOOLEAN DEFAULT TRUE,
      triggered   INT DEFAULT 0,
      last_triggered_at TIMESTAMPTZ,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS performance_metrics (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      metric_name TEXT NOT NULL,
      value       DECIMAL(14,4),
      unit        TEXT,
      tags        JSONB DEFAULT '{}',
      recorded_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_metrics_name ON performance_metrics(metric_name);
    CREATE INDEX IF NOT EXISTS idx_metrics_time ON performance_metrics(recorded_at);

    CREATE TABLE IF NOT EXISTS scheduled_reports (
      id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id     UUID REFERENCES tenants(id),
      name          TEXT NOT NULL,
      template      TEXT NOT NULL,
      format        TEXT DEFAULT 'PDF',
      frequency     TEXT DEFAULT 'weekly',
      recipients    TEXT[] DEFAULT '{}',
      active        BOOLEAN DEFAULT TRUE,
      last_run_at   TIMESTAMPTZ,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );

    /* ──────────────────────────────────────────────────────────────────────
       PHASE 10 — SCORM, H5P, SSO
    ────────────────────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS scorm_packages (
      id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id       UUID REFERENCES tenants(id),
      course_id       UUID REFERENCES courses(id),
      title           TEXT NOT NULL,
      version         TEXT NOT NULL,
      storage_path    TEXT,
      manifest        JSONB DEFAULT '{}',
      status          TEXT DEFAULT 'active',
      completions     INT DEFAULT 0,
      avg_score       DECIMAL(5,2) DEFAULT 0,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scorm_tracking (
      id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      package_id    UUID REFERENCES scorm_packages(id) ON DELETE CASCADE,
      user_id       UUID REFERENCES users(id),
      cmi_data      JSONB DEFAULT '{}',
      score_raw     DECIMAL(5,2),
      score_min     DECIMAL(5,2),
      score_max     DECIMAL(5,2),
      completion    TEXT DEFAULT 'incomplete',
      success       TEXT DEFAULT 'unknown',
      total_time    TEXT,
      last_xapi_statement JSONB,
      updated_at    TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(package_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS h5p_content (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id),
      course_id   UUID REFERENCES courses(id),
      title       TEXT NOT NULL,
      h5p_type    TEXT NOT NULL,
      content     JSONB DEFAULT '{}',
      library     TEXT,
      uses        INT DEFAULT 0,
      status      TEXT DEFAULT 'active',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sso_providers (
      id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id     UUID REFERENCES tenants(id) ON DELETE CASCADE,
      name          TEXT NOT NULL,
      protocol      TEXT NOT NULL,
      entity_id     TEXT,
      sso_url       TEXT,
      slo_url       TEXT,
      certificate   TEXT,
      attribute_map JSONB DEFAULT '{}',
      active        BOOLEAN DEFAULT FALSE,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );


    CREATE TABLE IF NOT EXISTS drm_policies (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE UNIQUE,
      policy      JSONB NOT NULL DEFAULT '{}',
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_drm_policies_tenant ON drm_policies(tenant_id);

    /* policy_overrides column on license_profiles (if not exists) */
    ALTER TABLE license_profiles ADD COLUMN IF NOT EXISTS policy_overrides JSONB DEFAULT '{}';

    CREATE TABLE IF NOT EXISTS sso_sessions (
      id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id        UUID REFERENCES users(id) ON DELETE CASCADE,
      provider_id    UUID REFERENCES sso_providers(id),
      name_id        TEXT,
      session_index  TEXT,
      expires_at     TIMESTAMPTZ,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    );
  `;

  try {
    await query(SCHEMA);
    logger.info('✅  DB schema migrated');
    await seedSystemData();
  } catch (err) {
    logger.error('Migration failed:', err.message);
    // Don't throw — allow app to start with existing schema
  }
}

async function seedSystemData() {
  // System roles
  const systemRoles = [
    { name:'Super Admin', permissions:{ all:true } },
    { name:'Admin',       permissions:{ users:['r','c','u','d'], courses:['r','c','u','d'], grades:['r','c','u','d'], payments:['r'] } },
    { name:'Instructor',  permissions:{ courses:['r','c','u'],   grades:['r','c','u'],      messaging:['r','c'] } },
    { name:'Student',     permissions:{ courses:['r'],            grades:['r'],              messaging:['r','c'] } },
    { name:'Course Manager', permissions:{ courses:['r','c','u','d'], grades:['r','u'] } },
    { name:'Teaching Assistant', permissions:{ courses:['r'], grades:['r','c','u'], messaging:['r','c'] } },
  ];
  for (const role of systemRoles) {
    await query(
      `INSERT INTO roles (name, permissions, is_system)
       VALUES ($1,$2,TRUE)
       ON CONFLICT DO NOTHING`,
      [role.name, JSON.stringify(role.permissions)]
    );
  }
}

module.exports = { query, transaction, initDB, getPool };
