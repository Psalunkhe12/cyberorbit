import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { ThreatVector } from '../types';

export interface ThreatIndicatorRecord {
  id: string;
  origin: string;
  target: string;
  originCode: string;
  targetCode: string;
  riskScore: number;
  riskLabel: string;
  attackType: string;
  isIsolated: boolean;
  lastUpdated: string;
}

export function useRealtimeThreatIntel() {
  const [indicators, setIndicators] = useState<ThreatIndicatorRecord[]>([]);
  const [primaryVector, setPrimaryVector] = useState<ThreatVector | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchThreatIntel = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const { data, error } = await supabase
        .from('threat_indicators')
        .select('*')
        .order('risk_score', { ascending: false });

      if (error) throw error;

      if (data && data.length > 0) {
        const normalized: ThreatIndicatorRecord[] = data.map((item: any) => ({
          id: String(item.id),
          origin: item.origin || 'Unknown Origin',
          target: item.target || 'Unknown Target',
          originCode: item.origin_code || 'XX',
          targetCode: item.target_code || 'XX',
          riskScore: item.risk_score || 50,
          riskLabel: item.risk_label ? `${item.risk_label} ${item.risk_score}/100` : `Risk ${item.risk_score}/100`,
          attackType: item.attack_type || 'Network Intrusion',
          isIsolated: Boolean(item.is_isolated),
          lastUpdated: item.last_updated || new Date().toISOString(),
        }));

        setIndicators(normalized);

        const topItem = normalized[0];
        setPrimaryVector({
          origin: topItem.origin,
          target: topItem.target,
          originCode: topItem.originCode,
          targetCode: topItem.targetCode,
          riskScore: topItem.riskScore,
          riskLabel: topItem.riskLabel,
          attackType: topItem.attackType,
          isIsolated: topItem.isIsolated,
        });
      } else {
        setIndicators([]);
        setPrimaryVector(null);
      }
    } catch (err: any) {
      console.warn('[useRealtimeThreatIntel] Supabase fetch error:', err.message);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const isolateThreatVector = async (id?: string) => {
    if (primaryVector) {
      setPrimaryVector((prev) => (prev ? { ...prev, isIsolated: true } : null));
    }

    if (supabase && id) {
      try {
        await supabase
          .from('threat_indicators')
          .update({ is_isolated: true, last_updated: new Date().toISOString() })
          .eq('id', id);
      } catch (err) {
        console.warn('[useRealtimeThreatIntel] Supabase isolate error:', err);
      }
    }
  };

  useEffect(() => {
    fetchThreatIntel();

    if (!supabase) return;

    const channel = supabase
      .channel('realtime:threat_indicators')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'threat_indicators' },
        () => {
          fetchThreatIntel();
        }
      )
      .subscribe();

    return () => {
      if (supabase && channel) {
        supabase.removeChannel(channel);
      }
    };
  }, [fetchThreatIntel]);

  return {
    indicators,
    primaryVector,
    loading,
    error,
    isolateThreatVector,
    reload: fetchThreatIntel,
  };
}
