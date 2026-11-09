import { auth as firebaseAuth, create, find, update } from './db.js';

const authError = (error) => error?.code?.startsWith('auth/') || error?.code === 'app/invalid-credential';

export async function verifyFirebaseToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) throw Object.assign(new Error('Not signed in'), { status: 401 });
  return firebaseAuth.verifyIdToken(header.slice(7), true);
}

export async function auth(req, res, next) {
  try {
    const decoded = await verifyFirebaseToken(req);
    if (!decoded.email_verified) return res.status(403).json({ error: 'Verify your email first', needsVerify: true });
    const user = await find('users', 'firebase_uid', decoded.uid);
    if (!user) return res.status(403).json({ error: 'Account profile not found' });
    if (user.status === 'unverified' && decoded.email_verified) {
      user.status = 'active';
      await update('users', user.id, { status: 'active' });
      if (user.role !== 'client') {
        await create('notifications', {
          user_id: user.id, title: 'Welcome to Fixify',
          body: 'Upload your permit or ID so an administrator can validate your account, then subscribe to start accepting bookings.',
          read: false, created_at: Math.floor(Date.now() / 1000),
        });
      }
    }
    if (user.status !== 'active') return res.status(403).json({ error: 'Account is ' + user.status });
    req.firebaseUser = decoded;
    req.user = user;
    return next();
  } catch (error) {
    if (error.status === 401 || authError(error) || error.code === 'auth/id-token-revoked' || error.code === 'auth/id-token-expired') {
      return res.status(401).json({ error: error.status === 401 ? error.message : 'Session expired' });
    }
    return next(error);
  }
}

export const role = (...roles) => (req, res, next) => (roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Not allowed' }));
export const perm = (permission) => (req, res, next) => {
  const permissions = Array.isArray(req.user.permissions) ? req.user.permissions : [];
  return permissions.includes('*') || permissions.includes(permission)
    ? next() : res.status(403).json({ error: 'Missing admin permission: ' + permission });
};
export const audit = (req, action, target, meta) => create('audit_logs', {
  actor_id: req?.user?.id ?? null, action, target: target ?? null, meta: meta ?? null,
  ip: req?.ip ?? null, created_at: Math.floor(Date.now() / 1000),
});
export const notify = (userId, title, body) => create('notifications', {
  user_id: userId, title, body: body ?? '', read: false, created_at: Math.floor(Date.now() / 1000),
});
export const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ error: result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ') });
  req.body = result.data;
  next();
};
export const safeUser = (user) => {
  if (!user) return user;
  const { firebase_uid, password_hash, code_hash, code_expires, code_purpose, code_tries, failed_attempts, locked_until, token_version, ...rest } = user;
  return { ...rest, permissions: JSON.stringify(Array.isArray(rest.permissions) ? rest.permissions : []) };
};
