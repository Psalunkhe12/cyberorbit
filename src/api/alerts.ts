import { supabase } from '../lib/supabase';

export async function getAlerts() {
    if (!supabase) {
        throw new Error('Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.');
    }

    const { data, error } = await supabase
        .from('alerts')
        .select('*')
        .order('detected_at', { ascending: false });

    if (error) {
        throw error;
    }

    return data;
}