import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { AnomalyEvent } from '../types';
import { INITIAL_ANOMALIES } from '../data/mockData';

/**
 * Normalizes raw Supabase database row to AnomalyEvent TypeScript model.
 */
function normalizeAlertRecord(row: any): AnomalyEvent {
  const rawStatus = String(row.status || 'UNREVIEWED').toUpperCase();
  let status: AnomalyEvent['status'] = 'UNREVIEWED';

  if (rawStatus === 'ACKNOWLEDGED' || rawStatus === 'INVESTIGATING' || rawStatus === 'CONFIRMED') {
    status = 'CONFIRMED';
  } else if (rawStatus === 'CONTAINED' || rawStatus === 'RESOLVED' || rawStatus === 'MITIGATED') {
    status = 'MITIGATED';
  } else if (rawStatus === 'FALSE_POSITIVE' || rawStatus === 'DISMISSED') {
    status = 'DISMISSED';
  } else {
    status = 'UNREVIEWED';
  }

  return {
    id: String(row.id || `evt-${Date.now()}`),
    severity: row.severity || 'MEDIUM',
    event: row.event || 'Security Anomaly',
    ip: row.ip || row.source_ip || '0.0.0.0',
    asset: row.asset || row.target_asset || 'unknown-asset',
    timestamp: row.timestamp || row.detected_at || new Date().toISOString(),
    status,
    confidence: typeof row.confidence === 'number' ? row.confidence : 80,
    payloadSnippet: row.payload_snippet || row.payloadSnippet || 'N/A',
    geoOrigin: row.geo_origin || row.geoOrigin || 'UNKNOWN',
    cveId: row.cve_id || row.cveId,
    attackVector: row.attack_vector || row.attackVector || 'Network Intrusion',
  };
}

export function useRealtimeAlerts(initialFallback: AnomalyEvent[] = []) {
  const [alerts, setAlerts] = useState<AnomalyEvent[]>(initialFallback);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(false);

  const fetchAlerts = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError(null);
      let queryRes = await supabase
        .from('alerts')
        .select('*')
        .order('detected_at', { ascending: false });

      if (queryRes.error) {
        // Fallback to default select if detected_at ordering fails
        queryRes = await supabase.from('alerts').select('*');
      }

      if (queryRes.error) throw queryRes.error;

      if (queryRes.data) {
        const normalized = queryRes.data.map(normalizeAlertRecord);
        setAlerts(normalized);
      }
    } catch (err: any) {
      console.warn('[useRealtimeAlerts] Fetching from Supabase failed:', err.message);
      setError(err.message || 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();

    if (!supabase) {
      setIsLive(false);
      return;
    }

    // Subscribe to realtime changes on the 'alerts' table
    const channel = supabase
      .channel('realtime:alerts')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'alerts' },
        (payload) => {
          if (payload.eventType === 'INSERT') {
            const newRecord = normalizeAlertRecord(payload.new);
            setAlerts((prev) => [newRecord, ...prev.filter((a) => a.id !== newRecord.id)]);
          } else if (payload.eventType === 'UPDATE') {
            const updatedRecord = normalizeAlertRecord(payload.new);
            setAlerts((prev) => prev.map((a) => (a.id === updatedRecord.id ? updatedRecord : a)));
          } else if (payload.eventType === 'DELETE') {
            const oldId = String(payload.old?.id);
            setAlerts((prev) => prev.filter((a) => a.id !== oldId));
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
  }, [fetchAlerts]);

  return {
    alerts,
    setAlerts,
    loading,
    error,
    isLive,
    reload: fetchAlerts,
  };
}
