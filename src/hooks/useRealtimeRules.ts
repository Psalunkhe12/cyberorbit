import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { SecurityRule } from '../types';

export function useRealtimeRules() {
  const [rules, setRules] = useState<SecurityRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRules = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const { data, error } = await supabase
        .from('security_rules')
        .select('*')
        .order('priority', { ascending: true });

      if (error) throw error;

      if (data) {
        const normalized: SecurityRule[] = data.map((r: any) => ({
          id: String(r.id),
          name: r.name || 'Security Rule',
          pattern: r.pattern || '*',
          action: (r.action as any) || 'BLOCK',
          status: r.status === 'PAUSED' ? 'PAUSED' : 'ACTIVE',
          matchesCount: typeof r.matches_count === 'number' ? r.matches_count : 0,
          priority: r.priority || 1,
          category: r.category || 'Web Application Firewall',
          lastTriggered: r.last_triggered
            ? new Date(r.last_triggered).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : 'Never',
        }));
        setRules(normalized);
      }
    } catch (err: any) {
      console.warn('[useRealtimeRules] Supabase fetch error:', err.message);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const toggleRuleStatus = async (id: string) => {
    const targetRule = rules.find((r) => r.id === id);
    if (!targetRule) return;

    const newStatus = targetRule.status === 'ACTIVE' ? 'PAUSED' : 'ACTIVE';
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, status: newStatus } : r))
    );

    if (supabase) {
      try {
        await supabase
          .from('security_rules')
          .update({ status: newStatus, updated_at: new Date().toISOString() })
          .eq('id', id);
      } catch (err) {
        console.warn('[useRealtimeRules] Supabase update error:', err);
      }
    }
  };

  const addRule = async (newRule: SecurityRule) => {
    setRules((prev) => [newRule, ...prev]);

    if (supabase) {
      try {
        await supabase.from('security_rules').insert([
          {
            name: newRule.name,
            pattern: newRule.pattern,
            action: newRule.action,
            status: newRule.status,
            priority: newRule.priority,
            category: newRule.category,
          },
        ]);
      } catch (err) {
        console.warn('[useRealtimeRules] Supabase insert error:', err);
      }
    }
  };

  useEffect(() => {
    fetchRules();

    if (!supabase) return;

    const channel = supabase
      .channel('realtime:security_rules')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'security_rules' },
        () => {
          fetchRules();
        }
      )
      .subscribe();

    return () => {
      if (supabase && channel) {
        supabase.removeChannel(channel);
      }
    };
  }, [fetchRules]);

  return {
    rules,
    setRules,
    loading,
    error,
    toggleRuleStatus,
    addRule,
    reload: fetchRules,
  };
}
