import { authenticator } from 'otplib';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { code } = req.body;
  const secret = process.env.TOTP_SECRET;

  if (!secret) {
    return res.status(500).json({ error: 'TOTP_SECRET not configured' });
  }

  const isValid = authenticator.verify({ token: code, secret });

  if (isValid) {
    return res.status(200).json({ token: 'granted' });
  } else {
    return res.status(401).json({ error: 'Invalid code' });
  }
}
