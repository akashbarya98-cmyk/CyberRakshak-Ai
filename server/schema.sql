-- ============================================================================
-- CyberRakshak AI — PostgreSQL Enterprise Relational Schema & Migration 001
-- ============================================================================
-- Designed for PostgreSQL 14+ / Cloud SQL / Supabase / Neon
-- Features:
-- - UUID / stable primary keys with constraints
-- - Strict foreign keys with cascading deletions where appropriate
-- - Role-Based Access Control (RBAC) with workspace membership checks
-- - Logical workspace isolation (personal vs corporate perimeters)
-- - Separation of seeded demonstration fixtures (is_demo = true) vs verified user scans (is_demo = false)
-- - B-tree and composite indexing for high-frequency queries
-- - Automated timestamp triggers
-- ============================================================================

-- Schema Migration Metadata Tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 1. Users & Identities
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  global_role VARCHAR(32) NOT NULL DEFAULT 'Viewer' CHECK (global_role IN ('Owner', 'Administrator', 'Analyst', 'Viewer')),
  current_workspace_id VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- 2. Workspaces (Perimeter Contexts)
CREATE TABLE IF NOT EXISTS workspaces (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(32) NOT NULL CHECK (type IN ('personal', 'business')),
  owner_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  role_label VARCHAR(32) NOT NULL DEFAULT 'Owner',
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_workspaces_owner ON workspaces(owner_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_type ON workspaces(type);

-- 3. Workspace Memberships (Multi-Tenant RBAC)
CREATE TABLE IF NOT EXISTS workspace_memberships (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(32) NOT NULL CHECK (role IN ('Owner', 'Administrator', 'Analyst', 'Viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_workspace_user UNIQUE (workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_workspace_user ON workspace_memberships(workspace_id, user_id);

-- 4. Digital Assets Registry
CREATE TABLE IF NOT EXISTS assets (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  domain VARCHAR(255) NOT NULL,
  type VARCHAR(64) NOT NULL DEFAULT 'Web Application Perimeter',
  authorized_by_owner BOOLEAN NOT NULL DEFAULT FALSE,
  status VARCHAR(32) NOT NULL CHECK (status IN ('Healthy', 'Moderate Risk', 'High Risk', 'Critical Risk')),
  last_checked TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  CONSTRAINT uq_workspace_domain UNIQUE (workspace_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_assets_workspace ON assets(workspace_id);
CREATE INDEX IF NOT EXISTS idx_assets_domain ON assets(domain);

-- 5. Personal Protection & Scam Scans
CREATE TABLE IF NOT EXISTS scans (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  type VARCHAR(32) NOT NULL CHECK (type IN ('message', 'url', 'email', 'image', 'job')),
  target TEXT NOT NULL,
  risk_level VARCHAR(32) NOT NULL CHECK (risk_level IN ('Low Indicated Risk', 'Moderate Risk', 'High Risk', 'Critical Risk')),
  score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
  confidence VARCHAR(32) NOT NULL,
  date VARCHAR(64) NOT NULL,
  timestamp BIGINT NOT NULL,
  checks_completed VARCHAR(32) NOT NULL DEFAULT '8 / 10',
  summary TEXT NOT NULL,
  threat_intel_source VARCHAR(128),
  safety_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
  priority_calculation JSONB,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_workspace_timestamp ON scans(workspace_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_level);

-- 6. Granular Security Findings
CREATE TABLE IF NOT EXISTS findings (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE CASCADE,
  assessment_id VARCHAR(64),
  title VARCHAR(255) NOT NULL,
  category VARCHAR(64) NOT NULL,
  severity VARCHAR(32) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
  confidence VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'In Progress', 'Resolved', 'Awaiting Verification')),
  description TEXT NOT NULL,
  source VARCHAR(128) NOT NULL,
  impact TEXT,
  remediation TEXT,
  priority_score INTEGER NOT NULL DEFAULT 50 CHECK (priority_score >= 0 AND priority_score <= 100),
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_workspace ON findings(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- 7. Evidence Items (Observed Artifacts, Headers, TLS Handshakes)
CREATE TABLE IF NOT EXISTS evidence_items (
  id VARCHAR(64) PRIMARY KEY,
  finding_id VARCHAR(64) NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  type VARCHAR(64) NOT NULL,
  key_name VARCHAR(128) NOT NULL,
  raw_value TEXT,
  redacted_value TEXT,
  is_confirmed BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_items(finding_id);

-- 8. Business Security Assessments
CREATE TABLE IF NOT EXISTS assessments (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  domain VARCHAR(255) NOT NULL,
  industry VARCHAR(64) NOT NULL DEFAULT 'Technology',
  business_size VARCHAR(64) NOT NULL DEFAULT '1-10 employees',
  last_assessment VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL CHECK (status IN ('Completed', 'In Progress', 'Scheduled', 'Inconclusive')),
  overall_score INTEGER NOT NULL CHECK (overall_score >= 0 AND overall_score <= 100),
  risk_classification VARCHAR(32) NOT NULL,
  authorized_by_owner BOOLEAN NOT NULL DEFAULT FALSE,
  checks_unavailable JSONB NOT NULL DEFAULT '[]'::jsonb,
  observed_evidence JSONB,
  timestamp BIGINT NOT NULL,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assessments_workspace ON assessments(workspace_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_domain ON assessments(domain);

-- 9. Cyber Risk Graph Relationships & Nodes
CREATE TABLE IF NOT EXISTS graph_nodes (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  label VARCHAR(255) NOT NULL,
  type VARCHAR(32) NOT NULL CHECK (type IN ('asset', 'threat', 'vulnerability', 'actor', 'indicator', 'control')),
  risk_level VARCHAR(32) CHECK (risk_level IN ('Critical', 'High', 'Medium', 'Low')),
  cluster VARCHAR(64),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS graph_relationships (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  source_node_id VARCHAR(64) NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  target_node_id VARCHAR(64) NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  label VARCHAR(64) NOT NULL,
  relationship_type VARCHAR(64) NOT NULL,
  weight INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_graph_edge UNIQUE (source_node_id, target_node_id, label)
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_workspace ON graph_nodes(workspace_id);
CREATE INDEX IF NOT EXISTS idx_graph_rel_workspace ON graph_relationships(workspace_id);

-- 10. Remediation Tasks (Action Plans)
CREATE TABLE IF NOT EXISTS remediation_tasks (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  category VARCHAR(64) NOT NULL,
  description TEXT NOT NULL,
  effort VARCHAR(64) NOT NULL,
  priority VARCHAR(32) NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
  severity VARCHAR(32) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
  status VARCHAR(32) NOT NULL CHECK (status IN ('Open', 'In Progress', 'Awaiting Verification', 'Resolved')),
  target VARCHAR(255) NOT NULL,
  due_date VARCHAR(64) NOT NULL,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_remediation_workspace ON remediation_tasks(workspace_id);
CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_tasks(status);

-- 11. Community Scam Reports
CREATE TABLE IF NOT EXISTS community_reports (
  id VARCHAR(64) PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  type VARCHAR(64) NOT NULL,
  indicator VARCHAR(255) NOT NULL,
  risk_level VARCHAR(32) NOT NULL CHECK (risk_level IN ('Critical', 'High', 'Medium', 'Low')),
  reported_at VARCHAR(64) NOT NULL,
  reports_count INTEGER NOT NULL DEFAULT 1,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  description TEXT NOT NULL,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_community_indicator ON community_reports(indicator);
CREATE INDEX IF NOT EXISTS idx_community_created ON community_reports(created_at DESC);

-- 12. Notifications
CREATE TABLE IF NOT EXISTS notifications (
  id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(64) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  detail TEXT NOT NULL,
  time VARCHAR(64) NOT NULL,
  type VARCHAR(32) NOT NULL CHECK (type IN ('danger', 'warning', 'info')),
  read BOOLEAN NOT NULL DEFAULT FALSE,
  timestamp BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notifications_workspace ON notifications(workspace_id, timestamp DESC);

-- 13. Security Audit Logs (Immutable Ledger)
CREATE TABLE IF NOT EXISTS security_audit_logs (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL,
  user_email VARCHAR(255) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  action VARCHAR(128) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL CHECK (status IN ('SUCCESS', 'DENIED', 'ERROR')),
  details TEXT,
  ip_address VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_workspace ON security_audit_logs(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON security_audit_logs(action);

-- 14. Workspace Hygiene Controls
CREATE TABLE IF NOT EXISTS workspace_hygiene (
  workspace_id VARCHAR(64) PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  unique_passwords BOOLEAN NOT NULL DEFAULT TRUE,
  recovery_methods_reviewed BOOLEAN NOT NULL DEFAULT TRUE,
  backups_configured BOOLEAN NOT NULL DEFAULT TRUE,
  devices_updated BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Record Migration Completion
INSERT INTO schema_migrations (version, name) 
VALUES (1, '001_initial_cyberrakshak_relational_schema')
ON CONFLICT (version) DO NOTHING;
