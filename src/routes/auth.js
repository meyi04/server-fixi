import { Router } from 'express';
import { z } from 'zod';
import { auth as firebaseAuth, createUser, find } from '../db.js';
import { auth, verifyFirebaseToken, validate, audit, safeUser, notify } from '../mw.js';

const r = Router();

r.post('/register', validate(z.object({
  role: z.enum(['client', 'shop', 'technician']), name: z.string().min(2).max(80),
  phone: z.string().max(20).optional(), businessName: z.string().max(100).optional(), city: z.string().max(80).optional(),
})), async (req, res) => {
  let identity;
  try {
    identity = await verifyFirebaseToken(req);
  } catch {
    return res.status(401).json({ error: 'Sign in with Firebase before creating an account profile' });
  }
  if (!identity.email || !identity.uid) return res.status(400).json({ error: 'A Firebase email account is required' });
  const body = req.body;
  if (body.role === 'shop' && !body.businessName) return res.status(400).json({ error: 'Business name is required' });
  const linked = await find('users', 'firebase_uid', identity.uid);
  if (linked) return res.status(200).json({ message: 'Account profile already exists' });

  const duplicate = await find('users', 'email', identity.email.toLowerCase());
  if (duplicate) return res.status(409).json({ error: 'Email is already linked to another account' });
  const id = await createUser({
    firebase_uid: identity.uid,
    role: body.role,
    name: body.name,
    email: identity.email.toLowerCase(),
    phone: body.phone ?? null,
    status: identity.email_verified ? 'active' : 'unverified',
    permissions: [],
    created_at: Math.floor(Date.now() / 1000),
  }, { business_name: body.businessName ?? null, city: body.city ?? null });
  if (id === null) return res.status(409).json({ error: 'An account already uses this email' });
  await audit({ user: { id }, ip: req.ip }, 'user.register', `user:${id}`, { role: body.role });
  res.status(201).json({ message: 'Account profile created' });
});

r.get('/me', auth, (req, res) => res.json(safeUser(req.user)));
r.post('/logout-all', auth, async (req, res) => {
  await firebaseAuth.revokeRefreshTokens(req.firebaseUser.uid);
  res.json({ ok: true });
});
r.post('/password', auth, (_req, res) => res.status(410).json({ error: 'Use Firebase Authentication to change your password' }));
r.post('/verify', (_req, res) => res.status(410).json({ error: 'Verify your email using the link sent by Firebase Authentication' }));
r.post('/resend', (_req, res) => res.status(410).json({ error: 'Request a verification email from the app' }));
r.post('/forgot', (_req, res) => res.status(410).json({ error: 'Request a password reset email from the app' }));
r.post('/reset', (_req, res) => res.status(410).json({ error: 'Reset your password using the link sent by Firebase Authentication' }));

export default r;
