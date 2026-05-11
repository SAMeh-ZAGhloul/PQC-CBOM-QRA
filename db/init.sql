-- ============================================================
-- CBOM Platform — PostgreSQL 16 Schema
-- File: db/init.sql
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";      -- for LIKE/ILIKE indexes
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- ── RBAC Enum ────────────────────────────────────────────────────────────────
CREATE TYPE rbac_role AS ENUM ('admin', 'engineer', 'ciso', 'auditor', 'ceo');

-- ── Quantum Classification Enum ──────────────────────────────────────────────
CREATE TYPE quantum_class AS ENUM (
  'vulnerable',      -- RSA, ECC, DH — broken by Shor's algorithm
  'partially_safe',  -- AES-128, SHA-256 — weakened by Grover's
  'safe',            -- AES-256, SHA3 — quantum-resistant
  'pqc',             -- ML-KEM, ML-DSA, SLH-DSA — NIST standardized
  'unknown'          -- classification pending
);

-- ── Crypto Type Enum ─────────────────────────────────────────────────────────
CREATE TYPE crypto_type AS ENUM (
  'asymmetric_encryption',
  'digital_signature',
  'key_exchange',
  'symmetric_encryption',
  'hash',
  'mac',
  'kdf',
  'pqc_kem',
  'pqc_signature',
  'unknown'
);

-- ── Finding Status Enum ──────────────────────────────────────────────────────
CREATE TYPE finding_status AS ENUM (
  'open',
  'in_progress',
  'resolved',
  'accepted_risk'
);

-- ── Finding Severity Enum ────────────────────────────────────────────────────
CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- ── Scan Status Enum ─────────────────────────────────────────────────────────
CREATE TYPE scan_status AS ENUM (
  'queued',
  'running',
  'partial',
  'complete',
  'failed',
  'cancelled'
);

-- ── Discovery Source Enum ────────────────────────────────────────────────────
CREATE TYPE discovery_source AS ENUM (
  'zeek_network',
  'ast_scanner',
  'binary_scanner',
  'cert_scanner',
  'db_scanner',
  'slm_fallback',
  'manual'
);

-- ============================================================
-- USERS AND RBAC
-- ============================================================

CREATE TABLE groups (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name          VARCHAR(100) NOT NULL UNIQUE,
  rbac_role     rbac_role NOT NULL,
  description   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email           VARCHAR(255) NOT NULL UNIQUE,
  password_hash   VARCHAR(255) NOT NULL,        -- bcrypt, cost 12
  display_name    VARCHAR(100),
  is_active       BOOLEAN NOT NULL DEFAULT TRUE,
  is_admin        BOOLEAN NOT NULL DEFAULT FALSE,
  last_login_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_groups (
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, group_id)
);

CREATE TABLE user_sessions (
  jti           UUID PRIMARY KEY,               -- JWT ID — used for revocation
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at    TIMESTAMPTZ NOT NULL,
  revoked_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  user_agent    TEXT,
  ip_address    INET
);

-- Indexes
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

-- ============================================================
-- SCANS
-- ============================================================

CREATE TABLE scans (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name              VARCHAR(255),
  status            scan_status NOT NULL DEFAULT 'queued',
  config            JSONB NOT NULL DEFAULT '{}',
    -- config fields:
    -- target_repos: string[]
    -- target_hosts: string[]
    -- target_db_connections: string[] (encrypted)
    -- network_interface: string
    -- max_file_depth: int (default 5)
    -- enable_llm_fallback: bool
    -- sector: string (for QARS scoring)
    -- q_day_year: int (default 2030)
  created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at        TIMESTAMPTZ,
  completed_at      TIMESTAMPTZ,
  error_message     TEXT,
  assets_found      INTEGER NOT NULL DEFAULT 0,
  files_scanned     INTEGER NOT NULL DEFAULT 0,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_jobs (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  job_type      VARCHAR(50) NOT NULL,  -- ast, binary, cert, db, zeek, slm
  status        scan_status NOT NULL DEFAULT 'queued',
  queue_name    VARCHAR(100),
  target        TEXT,                  -- file path, host, or db connection
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  error_message TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_by ON scans(created_by);
CREATE INDEX idx_scan_jobs_scan_id ON scan_jobs(scan_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);

-- ============================================================
-- CBOM — CRYPTO ASSETS
-- ============================================================

CREATE TABLE cbom_versions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  version_number  INTEGER NOT NULL DEFAULT 1,
  cyclonedx_json  JSONB,                        -- full CycloneDX 1.6 JSON
  minio_key       VARCHAR(500),                 -- path in MinIO cbom-exports bucket
  asset_count     INTEGER NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (scan_id, version_number)
);

CREATE TABLE crypto_assets (
  id                  UUID NOT NULL DEFAULT uuid_generate_v4(),
  dedup_hash          VARCHAR(64) NOT NULL,  -- UUID5(algo+location+keysize)
  cbom_version_id     UUID REFERENCES cbom_versions(id) ON DELETE SET NULL,
  scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

  -- Algorithm info
  algorithm           VARCHAR(100) NOT NULL,
  algorithm_normalized VARCHAR(100) NOT NULL,   -- uppercase, no dashes
  key_size            INTEGER,                  -- bits
  crypto_type         crypto_type NOT NULL DEFAULT 'unknown',
  quantum_class       quantum_class NOT NULL DEFAULT 'unknown',
  pqc_replacement     VARCHAR(100),             -- ML-KEM-768, ML-DSA-65, etc.

  -- Location
  location            TEXT NOT NULL,            -- file path, host:port, db.table
  line_number         INTEGER,
  source              discovery_source NOT NULL,

  -- Context
  library             VARCHAR(200),
  usage_context       TEXT,                     -- JWT signing, TLS, data-at-rest
  confidence          VARCHAR(10) NOT NULL DEFAULT 'medium',  -- high|medium|low

  -- Annotation (manual enrichment FR-C07)
  owner               VARCHAR(200),
  system_name         VARCHAR(200),
  data_classification VARCHAR(50),              -- public|internal|confidential|restricted
  migration_status    VARCHAR(50),              -- not_started|planned|in_progress|complete

  -- Lineage (FR-C05)
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  remediation_at      TIMESTAMPTZ,

  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Note: PostgreSQL requires any PRIMARY KEY / UNIQUE constraint on a partitioned
-- table to include the partition key. Global dedup_hash uniqueness must therefore
-- be enforced at the application layer or via a separate dedup registry table.

-- Partitions (quarterly — add more as needed)
CREATE TABLE crypto_assets_2025_q1 PARTITION OF crypto_assets
  FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE crypto_assets_2025_q2 PARTITION OF crypto_assets
  FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE crypto_assets_2025_q3 PARTITION OF crypto_assets
  FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE crypto_assets_2025_q4 PARTITION OF crypto_assets
  FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE crypto_assets_2026 PARTITION OF crypto_assets
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE crypto_assets_default PARTITION OF crypto_assets DEFAULT;

-- Indexes
CREATE INDEX idx_crypto_assets_scan_id ON crypto_assets(scan_id);
CREATE INDEX idx_crypto_assets_algorithm ON crypto_assets(algorithm_normalized);
CREATE INDEX idx_crypto_assets_quantum_class ON crypto_assets(quantum_class);
CREATE INDEX idx_crypto_assets_dedup_hash ON crypto_assets(dedup_hash);
CREATE INDEX idx_crypto_assets_last_seen ON crypto_assets(last_seen_at);

-- ============================================================
-- CERTIFICATES
-- ============================================================

CREATE TABLE certificates (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

  -- Certificate identity
  subject             TEXT NOT NULL,
  issuer              TEXT NOT NULL,
  serial_number       TEXT,
  is_ca               BOOLEAN NOT NULL DEFAULT FALSE,

  -- Key info
  key_algorithm       VARCHAR(100) NOT NULL,
  key_size            INTEGER,
  signature_algorithm VARCHAR(100) NOT NULL,
  quantum_class       quantum_class NOT NULL DEFAULT 'unknown',

  -- Validity
  valid_from          TIMESTAMPTZ,
  valid_until         TIMESTAMPTZ,
  is_expired          BOOLEAN,
  days_until_expiry   INTEGER,

  -- Fingerprints
  sha1_fingerprint    VARCHAR(60),
  sha256_fingerprint  VARCHAR(95),

  -- Location
  location            TEXT NOT NULL,           -- host:port or file path
  source              discovery_source NOT NULL,

  -- SANs
  sans                TEXT[],

  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_certs_scan_id ON certificates(scan_id);
CREATE INDEX idx_certs_valid_until ON certificates(valid_until);
CREATE INDEX idx_certs_sha256 ON certificates(sha256_fingerprint);
CREATE INDEX idx_certs_quantum_class ON certificates(quantum_class);

-- ============================================================
-- QARS SCORING
-- ============================================================

CREATE TABLE qars_scores (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  asset_id        UUID NOT NULL,
  asset_created_at TIMESTAMPTZ NOT NULL,
  scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

  -- Mosca components
  x_value         DECIMAL(5,2) NOT NULL,   -- data shelf life (years)
  y_value         DECIMAL(5,2) NOT NULL,   -- migration time (years)
  z_value         DECIMAL(5,2) NOT NULL,   -- years to Q-Day
  mosca_urgent    BOOLEAN NOT NULL,        -- TRUE when X + Y >= Z

  -- Weights
  sensitivity_weight DECIMAL(3,2) NOT NULL,  -- 0.5|1.0|1.5|2.0
  exposure_factor    DECIMAL(3,2) NOT NULL,  -- 0.5|1.0|1.5

  -- Scores
  base_qars       DECIMAL(4,3) NOT NULL,   -- 0.000–1.000
  weighted_qars   DECIMAL(4,3) NOT NULL,   -- 0.000–1.000 (final)
  severity        severity NOT NULL,

  -- Sector and compliance
  sector          VARCHAR(50) NOT NULL,
  compliance_gaps JSONB NOT NULL DEFAULT '[]',
    -- [{framework: "DORA", control_id: "ICT-2.1", description: "..."}]

  computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE qars_scores
  ADD CONSTRAINT qars_scores_asset_fk
  FOREIGN KEY (asset_id, asset_created_at)
  REFERENCES crypto_assets(id, created_at)
  ON DELETE CASCADE;

CREATE INDEX idx_qars_scores_asset_id ON qars_scores(asset_id);
CREATE INDEX idx_qars_scores_asset_ref ON qars_scores(asset_id, asset_created_at);
CREATE INDEX idx_qars_scores_scan_id ON qars_scores(scan_id);
CREATE INDEX idx_qars_scores_weighted ON qars_scores(weighted_qars DESC);
CREATE INDEX idx_qars_scores_severity ON qars_scores(severity);

-- ============================================================
-- QSRI SCORING
-- ============================================================

CREATE TABLE qsri_scores (
  id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id               UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

  -- Total score (0-100)
  total_score           DECIMAL(5,2) NOT NULL,

  -- Per-dimension maturity levels (0-5) and scores (0-100)
  dim_inventory_level       INTEGER NOT NULL CHECK (dim_inventory_level BETWEEN 0 AND 5),
  dim_risk_assessment_level INTEGER NOT NULL CHECK (dim_risk_assessment_level BETWEEN 0 AND 5),
  dim_crypto_agility_level  INTEGER NOT NULL CHECK (dim_crypto_agility_level BETWEEN 0 AND 5),
  dim_migration_level       INTEGER NOT NULL CHECK (dim_migration_level BETWEEN 0 AND 5),
  dim_tech_impl_level       INTEGER NOT NULL CHECK (dim_tech_impl_level BETWEEN 0 AND 5),
  dim_supply_chain_level    INTEGER NOT NULL CHECK (dim_supply_chain_level BETWEEN 0 AND 5),
  dim_governance_level      INTEGER NOT NULL CHECK (dim_governance_level BETWEEN 0 AND 5),
  dim_awareness_level       INTEGER NOT NULL CHECK (dim_awareness_level BETWEEN 0 AND 5),

  -- Improvement recommendations JSON
  recommendations       JSONB NOT NULL DEFAULT '[]',
    -- [{dimension: "...", current_level: 2, target_level: 3,
    --   recommendation: "...", effort: "low|medium|high",
    --   impact: "low|medium|high"}]

  -- Input tracking
  cbom_coverage_pct     DECIMAL(5,2),   -- auto-populated from CBOM
  assessment_input      JSONB,          -- manual answers from UI

  computed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_qsri_scores_scan_id ON qsri_scores(scan_id);

-- ============================================================
-- FINDINGS
-- ============================================================

CREATE TABLE findings (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  asset_id        UUID,
  asset_created_at TIMESTAMPTZ,
  cert_id         UUID REFERENCES certificates(id) ON DELETE SET NULL,
  scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

  -- Classification
  severity        severity NOT NULL,
  finding_type    VARCHAR(100) NOT NULL,  -- algorithm_risk, cert_expiry, weak_key, etc.
  title           VARCHAR(500) NOT NULL,
  description     TEXT NOT NULL,
  recommendation  TEXT NOT NULL,

  -- Workflow (FR-P06)
  status          finding_status NOT NULL DEFAULT 'open',
  owner_id        UUID REFERENCES users(id) ON DELETE SET NULL,
  due_date        DATE,
  rationale       TEXT,                 -- for accepted_risk status

  -- Compliance linkage
  framework       VARCHAR(50),          -- DORA, NIS2, NSM-10
  control_id      VARCHAR(100),

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT finding_has_target CHECK (asset_id IS NOT NULL OR cert_id IS NOT NULL)
);

ALTER TABLE findings
  ADD CONSTRAINT findings_asset_fk
  FOREIGN KEY (asset_id, asset_created_at)
  REFERENCES crypto_assets(id, created_at)
  ON DELETE SET NULL;

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_owner ON findings(owner_id);
CREATE INDEX idx_findings_due_date ON findings(due_date);

-- ============================================================
-- AUDIT LOG (Append-only, RLS enforced)
-- ============================================================

CREATE TABLE audit_log (
  id              BIGSERIAL PRIMARY KEY,
  actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
  actor_email     VARCHAR(255),          -- denormalized for immutability
  action          VARCHAR(100) NOT NULL, -- CREATE, UPDATE, DELETE, LOGIN, EXPORT, etc.
  resource_type   VARCHAR(100),          -- scan, finding, user, group, cbom, etc.
  resource_id     UUID,
  old_value       JSONB,
  new_value       JSONB,
  ip_address      INET,
  user_agent      TEXT,
  trace_id        UUID,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX idx_audit_log_action ON audit_log(action);

-- Row-Level Security: NO UPDATE OR DELETE ever
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Block ALL updates and deletes for every role including superuser
CREATE POLICY audit_log_no_update ON audit_log FOR UPDATE USING (FALSE);
CREATE POLICY audit_log_no_delete ON audit_log FOR DELETE USING (FALSE);
CREATE POLICY audit_log_insert ON audit_log FOR INSERT WITH CHECK (TRUE);
CREATE POLICY audit_log_select ON audit_log FOR SELECT USING (TRUE);

-- Revoke direct delete from app user
REVOKE DELETE ON audit_log FROM cbom;
REVOKE UPDATE ON audit_log FROM cbom;

-- ============================================================
-- SEED DATA — Default RBAC Groups
-- ============================================================

INSERT INTO groups (name, rbac_role, description) VALUES
  ('administrators',  'admin',    'Platform administrators — full access including user management'),
  ('security-team',   'engineer', 'Security engineers — scan execution, CBOM management, findings'),
  ('cisos',           'ciso',     'CISOs — risk dashboard, remediation approval, compliance export'),
  ('auditors',        'auditor',  'Auditors — read-only access, compliance export'),
  ('executives',      'ceo',      'CEO and board — executive KPI dashboard only');

-- ============================================================
-- HELPER FUNCTIONS
-- ============================================================

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_groups_updated_at BEFORE UPDATE ON groups
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_crypto_assets_updated_at BEFORE UPDATE ON crypto_assets
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- QARS coverage convenience view
CREATE VIEW v_scan_coverage AS
SELECT
  s.id AS scan_id,
  s.name,
  s.status,
  COUNT(ca.id) AS total_assets,
  COUNT(ca.id) FILTER (WHERE ca.quantum_class = 'vulnerable') AS vulnerable_count,
  COUNT(ca.id) FILTER (WHERE ca.quantum_class = 'partially_safe') AS partially_safe_count,
  COUNT(ca.id) FILTER (WHERE ca.quantum_class = 'safe') AS safe_count,
  COUNT(ca.id) FILTER (WHERE ca.quantum_class = 'pqc') AS pqc_count,
  AVG(qs.weighted_qars) AS avg_qars_score,
  MAX(qs.weighted_qars) AS max_qars_score
FROM scans s
LEFT JOIN crypto_assets ca ON ca.scan_id = s.id
LEFT JOIN qars_scores qs ON qs.asset_id = ca.id AND qs.scan_id = s.id
GROUP BY s.id, s.name, s.status;

-- Certificate expiry alert view
CREATE VIEW v_cert_expiry_alerts AS
SELECT
  c.*,
  s.name AS scan_name,
  CASE
    WHEN days_until_expiry <= 7  THEN 'critical'
    WHEN days_until_expiry <= 30 THEN 'high'
    WHEN days_until_expiry <= 90 THEN 'medium'
    ELSE 'low'
  END AS expiry_severity
FROM certificates c
JOIN scans s ON s.id = c.scan_id
WHERE valid_until > NOW()
  AND days_until_expiry <= 90
ORDER BY days_until_expiry;
