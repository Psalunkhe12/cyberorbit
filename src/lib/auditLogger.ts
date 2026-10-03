import { supabase } from './supabase';

export type AuditActionType =
  | 'LOGIN'
  | 'ALERT_ACKNOWLEDGED'
  | 'INCIDENT_CREATED'
  | 'INCIDENT_UPDATED'
  | 'INCIDENT_RESOLVED'
  | 'RULE_CREATED'
  | 'RULE_UPDATED'
  | 'AI_ANALYSIS_GENERATED'
  | 'RESPONSE_REQUESTED'
  | 'RESPONSE_APPROVED'
  | 'RESPONSE_REJECTED';

export interface AuditLogRecord {
  id: string;
  user: string;
  action: AuditActionType;
  entity: string;
  old_value: any;
  new_value: any;
  timestamp: string;
}

export const VALID_AUDIT_ACTIONS: AuditActionType[] = [
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
  'RESPONSE_REJECTED',
];

export async function logAuditAction(params: {
  user: string;
  action: AuditActionType;
  entity: string;
  old_value?: any;
  new_value?: any;
  timestamp?: string;
}): Promise<AuditLogRecord> {
  const { user, action, entity, old_value = null, new_value = null } = params;
  const timestamp = params.timestamp || new Date().toISOString();

  if (!VALID_AUDIT_ACTIONS.includes(action)) {
    throw new Error(`Invalid audit action '${action}'. Must be one of: ${VALID_AUDIT_ACTIONS.join(', ')}`);
  }

  const record: AuditLogRecord = {
    id: `audit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    user: user || 'SYSTEM',
    action,
    entity,
    old_value,
    new_value,
    timestamp,
  };

  // 1. Sync to Supabase if configured
  if (supabase) {
    try {
      await supabase.from('audit_logs').insert([
        {
          user: record.user,
          action: record.action,
          entity: record.entity,
          old_value: record.old_value,
          new_value: record.new_value,
          timestamp: record.timestamp,
        },
      ]);
    } catch (err) {
      console.warn('[AuditLogger] Supabase audit log insert fallback:', err);
    }
  }

  // 2. Sync to Express API server endpoint
  try {
    await fetch('/api/audit-logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(record),
    });
  } catch (err) {
    console.warn('[AuditLogger] Express server audit log sync fallback:', err);
  }

  return record;
}

export async function fetchAuditLogs(): Promise<AuditLogRecord[]> {
  // Try Supabase first if available
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('audit_logs')
        .select('*')
        .order('timestamp', { ascending: false });
      if (!error && data && data.length > 0) {
        return data as AuditLogRecord[];
      }
    } catch (err) {
      console.warn('[AuditLogger] Supabase fetch fallback to API:', err);
    }
  }

  // Fallback to Express backend API
  try {
    const res = await fetch('/api/audit-logs');
    if (res.ok) {
      const data = await res.json();
      return data;
    }
  } catch (err) {
    console.error('[AuditLogger] Failed to fetch audit logs:', err);
  }

  return [];
}
