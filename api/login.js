import { authenticator } from 'otplib';
import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { code } = req.body;
  const secret = process.env.TOTP_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'TOTP_SECRET not configured' });
  }

  const isValid = authenticator.verify({ token: code, secret });
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid code' });
  }

  // TOTP passed. Now mint a real Supabase session server-side —
  // the owner's Supabase password lives ONLY here, as a Vercel
  // environment variable. It is never sent to the browser.
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
  const ownerEmail = process.env.SUPABASE_OWNER_EMAIL;
  const ownerPassword = process.env.SUPABASE_OWNER_PASSWORD;

  if (!supabaseUrl || !supabaseAnonKey || !ownerEmail || !ownerPassword) {
    return res.status(500).json({ error: 'Supabase bridge not configured' });
  }

  const supabase = createClient(supabaseUrl, supabaseAnonKey);
  const { data, error } = await supabase.auth.signInWithPassword({
    email: ownerEmail,
    password: ownerPassword,
  });

  if (error || !data.session) {
    return res.status(500).json({ error: 'Supabase sign-in failed' });
  }

  return res.status(200).json({
    token: 'granted',
    sb_access_token: data.session.access_token,
    sb_refresh_token: data.session.refresh_token,
  });
}
