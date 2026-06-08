import { authenticator } from 'otplib';
import qrcode from 'qrcode';

export default async function handler(req, res) {
  const { setupKey } = req.query;

  if (!setupKey || setupKey !== process.env.SETUP_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const secret = process.env.TOTP_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'TOTP_SECRET not configured' });
  }

  const otpauth = authenticator.keyuri('admin', 'LVO Holdings LLC', secret);
  const qr = await qrcode.toDataURL(otpauth);

  return res.status(200).json({ qr, secret });
}
