-- CyberOrbit Security Operations Center (SOC) Database Migration
-- Migration: 001_security_monitoring.sql
-- Description: Safely initializes SOC security tables, indexes, constraints, seed rules, and RLS policies.

-- Enable pgcrypto / uuid extensions if missing
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==========================================
-- 0. PRESERVE & ENSURE ALERTS TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    event TEXT NOT NULL,
    ip TEXT NOT NULL,
    dest_ip TEXT,
    asset TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'UNREVIEWED' CHECK (status IN ('UNREVIEWED', 'CONFIRMED', 'MITIGATED', 'DISMISSED')),
    confidence INTEGER DEFAULT 80 CHECK (confidence BETWEEN 0 AND 100),
    payload_snippet TEXT,
    geo_origin TEXT DEFAULT 'UNKNOWN',
    attack_vector TEXT DEFAULT 'Network Intrusion',
    cve_id TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 1. NETWORK_EVENTS TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.network_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    event_type TEXT,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    packets_in BIGINT DEFAULT 0,
    packets_out BIGINT DEFAULT 0,
    duration NUMERIC,
    application TEXT,
    source TEXT DEFAULT 'suricata',
    raw_event JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 2. TRAFFIC_METRICS TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.traffic_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    throughput_mbps NUMERIC NOT NULL DEFAULT 0.0,
    packets_per_second NUMERIC NOT NULL DEFAULT 0.0,
    active_connections INTEGER NOT NULL DEFAULT 0,
    inbound_bytes BIGINT DEFAULT 0,
    outbound_bytes BIGINT DEFAULT 0,
    inbound_packets BIGINT DEFAULT 0,
    outbound_packets BIGINT DEFAULT 0,
    threat_count INTEGER DEFAULT 0,
    source TEXT DEFAULT 'collector',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 3. SECURITY_RULES TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.security_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_code TEXT UNIQUE,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('BLOCK', 'RATE_LIMIT', 'CHALLENGE', 'LOG')),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED')),
    matches_count BIGINT DEFAULT 0,
    priority INTEGER DEFAULT 1,
    category TEXT DEFAULT 'Web Application Firewall',
    last_triggered TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 4. INCIDENTS TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES public.alerts(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    status TEXT NOT NULL DEFAULT 'UNREVIEWED' CHECK (status IN ('UNREVIEWED', 'CONFIRMED', 'MITIGATED', 'DISMISSED')),
    source_ip TEXT,
    target_asset TEXT,
    attack_vector TEXT,
    confidence INTEGER DEFAULT 80 CHECK (confidence BETWEEN 0 AND 100),
    summary TEXT,
    assigned_to TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 5. AI_ANALYSES TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.ai_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES public.incidents(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES public.alerts(id) ON DELETE CASCADE,
    model_used TEXT NOT NULL DEFAULT 'gemini-3.6-flash',
    prompt_type TEXT NOT NULL,
    analysis_summary TEXT NOT NULL,
    risk_assessment TEXT,
    recommended_actions JSONB DEFAULT '[]'::jsonb,
    confidence_score NUMERIC CHECK (confidence_score BETWEEN 0 AND 100),
    raw_response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 6. THREAT_INDICATORS TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    origin TEXT NOT NULL,
    target TEXT NOT NULL,
    origin_code TEXT,
    target_code TEXT,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_label TEXT CHECK (risk_label IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    attack_type TEXT NOT NULL,
    is_isolated BOOLEAN DEFAULT false,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 7. RESPONSE_ACTIONS TABLE (Human-in-the-Loop Workflow)
-- ==========================================
CREATE TABLE IF NOT EXISTS public.response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requested_by TEXT NOT NULL DEFAULT 'Gemini SOC Copilot',
    approved_by TEXT DEFAULT 'Pending Analyst Review',
    action TEXT NOT NULL CHECK (action IN ('block_ip', 'investigate_host', 'monitor_traffic', 'isolate_host', 'BLOCK_IP', 'RATE_LIMIT', 'CHALLENGE')),
    target TEXT NOT NULL,
    reason TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXECUTED', 'SIMULATED', 'FAILED')),
    incident_id UUID REFERENCES public.incidents(id) ON DELETE SET NULL,
    alert_id UUID REFERENCES public.alerts(id) ON DELETE SET NULL,
    command_executed TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 8. AUDIT_LOGS TABLE (Structured Security Action Auditing)
-- ==========================================
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "user" TEXT NOT NULL DEFAULT 'SYSTEM',
    action TEXT NOT NULL CHECK (action IN (
        'LOGIN',
        'ALERT_ACKNOWLEDGED',
        'INCIDENT_CREATED',
        'INCIDENT_UPDATED',
        'INCIDENT_RESOLVED',
        'RULE_CREATED',
        'RULE_UPDATED',
        'AI_ANALYSIS_GENERATED',
        'RESPONSE_REQUESTED',
        'RESPONSE_APPROVED',
        'RESPONSE_REJECTED'
    )),
    entity TEXT NOT NULL,
    old_value JSONB,
    new_value JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- 9. NOTIFICATIONS TABLE
-- ==========================================
CREATE TABLE IF NOT EXISTS public.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    is_read BOOLEAN NOT NULL DEFAULT false,
    link TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==========================================
-- INDEXES FOR HIGH PERFORMANCE SOC SEARCH
-- ==========================================
CREATE INDEX IF NOT EXISTS idx_alerts_status ON public.alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON public.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON public.alerts(detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON public.network_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_events_src_ip ON public.network_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_dest_ip ON public.network_events(destination_ip);

CREATE INDEX IF NOT EXISTS idx_traffic_metrics_timestamp ON public.traffic_metrics(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_security_rules_status ON public.security_rules(status);

CREATE INDEX IF NOT EXISTS idx_incidents_severity ON public.incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON public.incidents(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_analyses_incident_id ON public.ai_analyses(incident_id);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_risk_score ON public.threat_indicators(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_response_actions_incident_id ON public.response_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON public.notifications(is_read);

-- Grant schema and table permissions for anon and authenticated roles
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;

ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.network_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.traffic_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

-- Create public read and write policies safely
DO $$ 
BEGIN
    -- Alerts Policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'alerts' AND policyname = 'Public select access for alerts') THEN
        CREATE POLICY "Public select access for alerts" ON public.alerts FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'alerts' AND policyname = 'Public insert access for alerts') THEN
        CREATE POLICY "Public insert access for alerts" ON public.alerts FOR INSERT WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'alerts' AND policyname = 'Public update access for alerts') THEN
        CREATE POLICY "Public update access for alerts" ON public.alerts FOR UPDATE USING (true);
    END IF;

    -- Network Events Policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'network_events' AND policyname = 'Public select access for network_events') THEN
        CREATE POLICY "Public select access for network_events" ON public.network_events FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'network_events' AND policyname = 'Public insert access for network_events') THEN
        CREATE POLICY "Public insert access for network_events" ON public.network_events FOR INSERT WITH CHECK (true);
    END IF;

    -- Traffic Metrics Policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'traffic_metrics' AND policyname = 'Public select access for traffic_metrics') THEN
        CREATE POLICY "Public select access for traffic_metrics" ON public.traffic_metrics FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'traffic_metrics' AND policyname = 'Public insert access for traffic_metrics') THEN
        CREATE POLICY "Public insert access for traffic_metrics" ON public.traffic_metrics FOR INSERT WITH CHECK (true);
    END IF;

    -- Security Rules Policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_rules' AND policyname = 'Public select access for security_rules') THEN
        CREATE POLICY "Public select access for security_rules" ON public.security_rules FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_rules' AND policyname = 'Public manage access for security_rules') THEN
        CREATE POLICY "Public manage access for security_rules" ON public.security_rules FOR ALL USING (true);
    END IF;

    -- Incidents Policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'incidents' AND policyname = 'Public select access for incidents') THEN
        CREATE POLICY "Public select access for incidents" ON public.incidents FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'incidents' AND policyname = 'Public insert/update access for incidents') THEN
        CREATE POLICY "Public insert/update access for incidents" ON public.incidents FOR ALL USING (true);
    END IF;

    -- AI Analyses Policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'ai_analyses' AND policyname = 'Public select access for ai_analyses') THEN
        CREATE POLICY "Public select access for ai_analyses" ON public.ai_analyses FOR SELECT USING (true);
    END IF;

    -- Threat Indicators Policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_indicators' AND policyname = 'Public select access for threat_indicators') THEN
        CREATE POLICY "Public select access for threat_indicators" ON public.threat_indicators FOR SELECT USING (true);
    END IF;

-- ==========================================
-- 9. USER_PROFILES TABLE & ROLE-BASED ACCESS CONTROL (RBAC)
-- Roles: ADMIN, SOC_LEAD, ANALYST, VIEWER
-- ==========================================
CREATE TABLE IF NOT EXISTS public.user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'ANALYST' CHECK (role IN ('ADMIN', 'SOC_LEAD', 'ANALYST', 'VIEWER')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

-- Helper function to fetch current authenticated user's role
CREATE OR REPLACE FUNCTION public.get_user_role()
RETURNS TEXT AS $$
  SELECT role FROM public.user_profiles WHERE user_id = auth.uid() OR email = (auth.jwt() ->> 'email');
$$ LANGUAGE sql SECURITY DEFINER STABLE;

-- RLS POLICIES: Database level enforcement preventing VIEWER roles from modifying data
-- 1. User Profiles RLS
IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'user_profiles' AND policyname = 'Read user profiles') THEN
    CREATE POLICY "Read user profiles" ON public.user_profiles FOR SELECT USING (true);
END IF;

-- 2. Response Actions RLS (Only ADMIN & SOC_LEAD can insert/update response decisions)
IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'response_actions' AND policyname = 'RBAC Response Actions Select') THEN
    CREATE POLICY "RBAC Response Actions Select" ON public.response_actions FOR SELECT USING (true);
END IF;
IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'response_actions' AND policyname = 'RBAC Response Actions Manage') THEN
    CREATE POLICY "RBAC Response Actions Manage" ON public.response_actions FOR ALL USING (public.get_user_role() IN ('ADMIN', 'SOC_LEAD'));
END IF;

-- 3. Security Rules RLS (Only ADMIN & SOC_LEAD can modify rules)
IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_rules' AND policyname = 'RBAC Security Rules Manage') THEN
    CREATE POLICY "RBAC Security Rules Manage" ON public.security_rules FOR ALL USING (public.get_user_role() IN ('ADMIN', 'SOC_LEAD'));
END IF;

-- 4. Alerts & Incidents RLS (VIEWER is read-only; ANALYST, SOC_LEAD, ADMIN can modify)
IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'alerts' AND policyname = 'RBAC Alerts Modify') THEN
    CREATE POLICY "RBAC Alerts Modify" ON public.alerts FOR ALL USING (public.get_user_role() IN ('ADMIN', 'SOC_LEAD', 'ANALYST'));
END IF;
IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'incidents' AND policyname = 'RBAC Incidents Modify') THEN
    CREATE POLICY "RBAC Incidents Modify" ON public.incidents FOR ALL USING (public.get_user_role() IN ('ADMIN', 'SOC_LEAD', 'ANALYST'));
END IF;

END $$;

-- ==========================================
-- SEED DEFAULT SECURITY RULES (IF MISSING)
-- ==========================================
INSERT INTO public.security_rules (rule_code, name, pattern, action, status, priority, category)
VALUES
    ('RL-1001', 'SQL Injection Guard', 'union select|\'' OR \''1\''=\''1|information_schema', 'BLOCK', 'ACTIVE', 1, 'Web Application Firewall'),
    ('RL-1002', 'Cross-Site Scripting (XSS)', '<script|javascript:|onerror=', 'CHALLENGE', 'ACTIVE', 2, 'Web Application Firewall'),
    ('RL-1003', 'RCE Command Execution', '; cat /etc/passwd|\| nc |\$(whoami)', 'BLOCK', 'ACTIVE', 1, 'Host Intrusion'),
    ('RL-1004', 'SYN Flood Rate Control', 'syn_flood|tcp_syn_surge', 'RATE_LIMIT', 'ACTIVE', 1, 'DDoS Mitigation')
ON CONFLICT (rule_code) DO NOTHING;

-- ==========================================
-- ENABLE SUPABASE REALTIME REPLICATION
-- ==========================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.alerts;
        ALTER PUBLICATION supabase_realtime ADD TABLE public.network_events;
        ALTER PUBLICATION supabase_realtime ADD TABLE public.traffic_metrics;
        ALTER PUBLICATION supabase_realtime ADD TABLE public.incidents;
        ALTER PUBLICATION supabase_realtime ADD TABLE public.notifications;
    END IF;
EXCEPTION
    WHEN duplicate_object THEN NULL;
    WHEN OTHERS THEN NULL;
END $$;

