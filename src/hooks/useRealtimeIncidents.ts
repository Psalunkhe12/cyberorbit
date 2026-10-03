import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { CyberIncident, IncidentStatusType, SeverityLevel } from '../types';

export interface NotificationRecord {
  id: string;
  title: string;
  message: string;
  severity: SeverityLevel | 'INFO';
  is_read: boolean;
  link?: string;
  created_at: string;
}

export const INITIAL_MOCK_INCIDENTS: CyberIncident[] = [
  {
    id: 'INC-8F4A2190',
    title: 'Multi-Vector TCP SYN & Port Probe Surge',
    severity: 'CRITICAL',
    status: 'OPEN',
    source_ip: '192.168.1.105',
    target_asset: 'edge-api-01 (Port 443)',
    attack_vector: 'DDoS / Port Scanning',
    confidence: 94,
    risk_score: 88,
    summary: 'Correlated 14 network anomalies across SYN floods and high-risk port probes targeting perimeter API nodes.',
    assigned_to: 'Sarah Chen (SOC Lead)',
    rule_ids: ['RL-2001', 'RL-2002', 'RL-2003', 'RL-2005'],
    alert_count: 14,
    evidence_summary: 'Observed 12,000 pps TCP SYN surge targeting port 443 | Port scan probe across ports 4444, 3389, 23 | Abnormal outbound response volume 180KB',
    related_alerts: [
      {
        id: 'alt-101',
        rule_id: 'RL-2002',
        rule_name: 'Possible SYN Flood',
        severity: 'CRITICAL',
        confidence: 94,
        source_ip: '192.168.1.105',
        destination_ip: '10.0.0.1',
        evidence: 'TCP SYN flood pattern identified. SYN count: 1240, TCP flags: syn',
        timestamp: '2026-10-03T16:30:00Z',
      },
      {
        id: 'alt-102',
        rule_id: 'RL-2003',
        rule_name: 'Port Scanning',
        severity: 'HIGH',
        confidence: 88,
        source_ip: '192.168.1.105',
        destination_ip: '10.0.0.1',
        evidence: 'Source IP probed 12 distinct destination ports ([22, 80, 443, 3389, 4444])',
        timestamp: '2026-10-03T16:31:15Z',
      },
      {
        id: 'alt-103',
        rule_id: 'RL-2005',
        rule_name: 'Suspicious Destination Port',
        severity: 'HIGH',
        confidence: 85,
        source_ip: '192.168.1.105',
        destination_ip: '10.0.0.1',
        evidence: 'Connection attempt targeting known high-risk suspicious port 4444',
        timestamp: '2026-10-03T16:32:04Z',
      },
    ],
    first_seen_at: '2026-10-03T16:30:00Z',
    last_seen_at: '2026-10-03T16:32:04Z',
    created_at: '2026-10-03T16:30:00Z',
    updated_at: '2026-10-03T16:32:04Z',
  },
  {
    id: 'INC-3B7D0145',
    title: 'Repeated Authentication Failures & Credential Stuffing',
    severity: 'HIGH',
    status: 'INVESTIGATING',
    source_ip: '172.16.0.44',
    target_asset: 'auth-gateway-01 (Port 443)',
    attack_vector: 'Credential Stuffing',
    confidence: 86,
    risk_score: 68,
    summary: 'Detected 48 failed connection/authentication events within 3 minutes targeting primary OAuth gateway.',
    assigned_to: 'Alex Mercer (Senior Threat Hunter)',
    rule_ids: ['RL-2004', 'RL-2006'],
    alert_count: 8,
    evidence_summary: '48 consecutive HTTP 401 Unauthorized responses from auth-gateway-01 | 18 repeated connection attempts within 60s',
    related_alerts: [
      {
        id: 'alt-201',
        rule_id: 'RL-2004',
        rule_name: 'Repeated Failed Connections',
        severity: 'HIGH',
        confidence: 86,
        source_ip: '172.16.0.44',
        destination_ip: '10.0.0.2',
        evidence: 'Observed 48 failed connection/authentication events, exceeding threshold of 5 failures.',
        timestamp: '2026-10-03T16:15:00Z',
      },
      {
        id: 'alt-202',
        rule_id: 'RL-2006',
        rule_name: 'Repeated Connection Attempts',
        severity: 'MEDIUM',
        confidence: 80,
        source_ip: '172.16.0.44',
        destination_ip: '10.0.0.2',
        evidence: 'Observed 18 connection attempts from 172.16.0.44 targeting asset auth-gateway-01.',
        timestamp: '2026-10-03T16:16:10Z',
      },
    ],
    first_seen_at: '2026-10-03T16:15:00Z',
    last_seen_at: '2026-10-03T16:16:10Z',
    created_at: '2026-10-03T16:15:00Z',
    updated_at: '2026-10-03T16:16:10Z',
  },
  {
    id: 'INC-9E11C402',
    title: 'Abnormal Outbound Data Transfer & Potential Exfiltration',
    severity: 'HIGH',
    status: 'ACKNOWLEDGED',
    source_ip: '10.0.0.15',
    target_asset: 'db-cluster-primary (Port 5432)',
    attack_vector: 'Data Exfiltration / Anomaly',
    confidence: 82,
    risk_score: 72,
    summary: 'High-volume outbound payload transfer exceeding baseline threshold detected from internal database server.',
    assigned_to: 'Elena Rostova (Incident Responder)',
    rule_ids: ['RL-2007'],
    alert_count: 5,
    evidence_summary: 'Outbound byte transfer of 450,000 bytes exceeded normal baseline threshold of 100,000 bytes.',
    related_alerts: [
      {
        id: 'alt-301',
        rule_id: 'RL-2007',
        rule_name: 'Abnormal Outbound Traffic',
        severity: 'HIGH',
        confidence: 82,
        source_ip: '10.0.0.15',
        destination_ip: '198.51.100.4',
        evidence: 'Outbound byte transfer of 450,000 bytes exceeded normal baseline threshold of 100,000 bytes.',
        timestamp: '2026-10-03T15:45:00Z',
      },
    ],
    first_seen_at: '2026-10-03T15:45:00Z',
    last_seen_at: '2026-10-03T15:48:20Z',
    created_at: '2026-10-03T15:45:00Z',
    updated_at: '2026-10-03T15:48:20Z',
  },
  {
    id: 'INC-1A90F882',
    title: 'Internal Subnet Scanning Attempt',
    severity: 'MEDIUM',
    status: 'CONTAINED',
    source_ip: '192.168.1.88',
    target_asset: 'bastion-ssh-01 (Port 22)',
    attack_vector: 'Reconnaissance',
    confidence: 78,
    risk_score: 42,
    summary: 'Internal workstation probing management ports across management VLAN.',
    assigned_to: 'Marcus Vance (SecOps Engineer)',
    rule_ids: ['RL-2003'],
    alert_count: 3,
    evidence_summary: 'Port scan probe across internal management interfaces',
    related_alerts: [],
    first_seen_at: '2026-10-03T14:10:00Z',
    last_seen_at: '2026-10-03T14:15:00Z',
    created_at: '2026-10-03T14:10:00Z',
    updated_at: '2026-10-03T14:15:00Z',
  },
];

export function useRealtimeIncidents() {
  const [incidents, setIncidents] = useState<CyberIncident[]>([]);
  const [notifications, setNotifications] = useState<NotificationRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(false);

  const fetchIncidents = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const [incRes, notifRes] = await Promise.all([
        supabase
          .from('incidents')
          .select('*')
          .order('created_at', { ascending: false }),
        supabase
          .from('notifications')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(20),
      ]);

      if (incRes.data) {
        const mappedIncidents: CyberIncident[] = incRes.data.map((row: any) => ({
          id: row.id || row.incident_id || `INC-${Date.now()}`,
          alert_id: row.alert_id,
          title: row.title || row.summary || 'Security Incident',
          severity: (row.severity || 'MEDIUM') as SeverityLevel,
          status: (row.status || 'OPEN') as IncidentStatusType,
          source_ip: row.source_ip || row.ip || '0.0.0.0',
          target_asset: row.target_asset || row.asset || 'internal-asset',
          attack_vector: row.attack_vector || row.attackVector || 'Network Spike',
          confidence: row.confidence || 80,
          risk_score: row.risk_score || (row.severity === 'CRITICAL' ? 88 : row.severity === 'HIGH' ? 68 : 45),
          summary: row.summary || row.payload_snippet || '',
          assigned_to: row.assigned_to || 'Unassigned',
          rule_ids: row.rule_ids || ['RL-2001'],
          alert_count: row.alert_count || 1,
          evidence_summary: row.evidence_summary || row.summary || '',
          related_alerts: row.related_alerts || [],
          first_seen_at: row.first_seen_at || row.created_at || new Date().toISOString(),
          last_seen_at: row.last_seen_at || row.updated_at || new Date().toISOString(),
          created_at: row.created_at || new Date().toISOString(),
          updated_at: row.updated_at || new Date().toISOString(),
        }));
        setIncidents(mappedIncidents);
      }

      if (notifRes.data) {
        setNotifications(notifRes.data as NotificationRecord[]);
      }
    } catch (err: any) {
      console.warn('[useRealtimeIncidents] Fetch error:', err.message);
      setError(err.message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, []);

  const updateIncidentStatus = async (incidentId: string, newStatus: IncidentStatusType) => {
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === incidentId
          ? { ...inc, status: newStatus, updated_at: new Date().toISOString() }
          : inc
      )
    );

    if (supabase) {
      try {
        await supabase
          .from('incidents')
          .update({
            status: newStatus,
            updated_at: new Date().toISOString(),
          })
          .eq('id', incidentId);
      } catch (err: any) {
        console.warn('[useRealtimeIncidents] Status update failed:', err);
      }
    }
  };

  const assignAnalyst = async (incidentId: string, analystName: string) => {
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === incidentId
          ? { ...inc, assigned_to: analystName, updated_at: new Date().toISOString() }
          : inc
      )
    );

    if (supabase) {
      try {
        await supabase
          .from('incidents')
          .update({
            assigned_to: analystName,
            updated_at: new Date().toISOString(),
          })
          .eq('id', incidentId);
      } catch (err: any) {
        console.warn('[useRealtimeIncidents] Analyst assignment failed:', err);
      }
    }
  };

  useEffect(() => {
    fetchIncidents();

    if (!supabase) {
      setIsLive(false);
      return;
    }

    const channel = supabase
      .channel('realtime:incidents_and_notifications')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'incidents' },
        (payload) => {
          if (payload.eventType === 'INSERT') {
            const raw = payload.new;
            const newInc: CyberIncident = {
              id: raw.id,
              title: raw.title || 'Security Incident',
              severity: raw.severity || 'MEDIUM',
              status: raw.status || 'OPEN',
              source_ip: raw.source_ip || '0.0.0.0',
              target_asset: raw.target_asset || 'unknown',
              attack_vector: raw.attack_vector || 'Intrusion',
              confidence: raw.confidence || 80,
              risk_score: raw.risk_score || 65,
              assigned_to: raw.assigned_to || 'Unassigned',
              first_seen_at: raw.first_seen_at || new Date().toISOString(),
              last_seen_at: raw.last_seen_at || new Date().toISOString(),
              created_at: raw.created_at || new Date().toISOString(),
              updated_at: raw.updated_at || new Date().toISOString(),
            };
            setIncidents((prev) => [newInc, ...prev.filter((i) => i.id !== newInc.id)]);
          } else if (payload.eventType === 'UPDATE') {
            const raw = payload.new;
            setIncidents((prev) =>
              prev.map((i) => (i.id === raw.id ? { ...i, ...raw } : i))
            );
          } else if (payload.eventType === 'DELETE') {
            const oldId = String(payload.old?.id);
            setIncidents((prev) => prev.filter((i) => i.id !== oldId));
          }
        }
      )
      .subscribe((status) => {
        setIsLive(status === 'SUBSCRIBED');
      });

    return () => {
      if (supabase && channel) {
        supabase.removeChannel(channel);
      }
    };
  }, [fetchIncidents]);

  return {
    incidents,
    setIncidents,
    notifications,
    loading,
    error,
    isLive,
    reload: fetchIncidents,
    updateIncidentStatus,
    assignAnalyst,
  };
}
