import { supabase } from '../lib/supabase';

export async function getNetworkEvents(limit = 100) {
  const { data, error } = await supabase
    .from('network_events')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(limit);

  if (error) {
    throw error;
  }

  return data;
}

export async function getTrafficMetrics(limit = 100) {
  const { data, error } = await supabase
    .from('traffic_metrics')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(limit);

  if (error) {
    throw error;
  }

  return data;
}