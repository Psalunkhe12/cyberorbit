/// <reference types="vite/client" />

import { createClient } from '@supabase/supabase-js';

const rawUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseUrl = rawUrl.trim().replace(/\.cos$/, '.co');
const supabaseAnonKey = (import.meta.env.VITE_SUPABASE_ANON_KEY || import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY || '').trim();

export const supabase = supabaseUrl && supabaseAnonKey
	? createClient(supabaseUrl, supabaseAnonKey)
	: null;

