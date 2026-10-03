import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { NetworkEvent, TrafficMetric } from '../types/network';

export function useRealtimeNetworkEvents() {
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [trafficMetrics, setTrafficMetrics] = useState<TrafficMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(false);

  const fetchInitialData = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const [eventsRes, metricsRes] = await Promise.all([
        supabase
          .from('network_events')
          .select('*')
          .order('timestamp', { ascending: false })
          .limit(100),
        supabase
          .from('traffic_metrics')
          .select('*')
          .order('timestamp', { ascending: false })
          .limit(50),
      ]);

      if (eventsRes.data) {
        setNetworkEvents(eventsRes.data as NetworkEvent[]);
      }
      if (metricsRes.data) {
        setTrafficMetrics(metricsRes.data as TrafficMetric[]);
      }
    } catch (err: any) {
      console.warn('[useRealtimeNetworkEvents] Fetch error:', err.message);
      setError(err.message || 'Failed to load network events');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInitialData();

    if (!supabase) {
      setIsLive(false);
      return;
    }

    // Subscribe to realtime network_events & traffic_metrics
    const channel = supabase
      .channel('realtime:network_monitoring')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'network_events' },
        (payload) => {
          if (payload.eventType === 'INSERT') {
            const newEv = payload.new as NetworkEvent;
            setNetworkEvents((prev) => [newEv, ...prev.filter((item) => item.id !== newEv.id)]);
          } else if (payload.eventType === 'UPDATE') {
            const updatedEv = payload.new as NetworkEvent;
            setNetworkEvents((prev) => prev.map((item) => (item.id === updatedEv.id ? updatedEv : item)));
          } else if (payload.eventType === 'DELETE') {
            const oldId = String(payload.old?.id);
            setNetworkEvents((prev) => prev.filter((item) => item.id !== oldId));
          }
        }
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'traffic_metrics' },
        (payload) => {
          if (payload.eventType === 'INSERT') {
            const newMetric = payload.new as TrafficMetric;
            setTrafficMetrics((prev) => [newMetric, ...prev.filter((m) => m.id !== newMetric.id)]);
          } else if (payload.eventType === 'UPDATE') {
            const updatedMetric = payload.new as TrafficMetric;
            setTrafficMetrics((prev) => prev.map((m) => (m.id === updatedMetric.id ? updatedMetric : m)));
          } else if (payload.eventType === 'DELETE') {
            const oldId = String(payload.old?.id);
            setTrafficMetrics((prev) => prev.filter((m) => m.id !== oldId));
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
  }, [fetchInitialData]);

  return {
    networkEvents,
    trafficMetrics,
    loading,
    error,
    isLive,
    reload: fetchInitialData,
  };
}
