const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.SUPABASE_URL || process.env.SUPERBASE_URL || 'https://example.supabase.co';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || process.env.SUPERBASE_ANON_KEY || 'placeholder-anon-key';

if (!process.env.SUPABASE_URL && !process.env.SUPERBASE_URL) {
  console.warn('Supabase environment variables are not set. The app will start, but database-backed routes will return configuration errors until they are provided.');
}

const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: false // Essential for server-side environments
  }
});

module.exports = supabase;
