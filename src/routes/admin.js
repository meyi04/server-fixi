import { Router } from 'express';
import { z } from 'zod';
import { auth as firebaseAuth, create, createAuthUser, get, list, remove, set, update } from '../db.js';
import { auth, role, perm, validate, audit, notify } from '../mw.js';

const r = Router();
r.use(auth, role('admin'));
const now = () => Math.floor(Date.now() / 1000);
const PERMS = ['users', 'documents', 'billing', 'finance', 'reports', 'content', 'admins', 'settings'];
const rowsBy = (collection, field, value) => list(collection, { where: [[field, '==', value]] });
const isSuper = (u) => (Array.isArray(u.permissions) ? u.permissions : []).includes('*');

r.get('/users', perm('users'), async (req, res) => {
  const { role: roleFilter, status, q } = req.query;
  let users = await list('users');
  if (roleFilter) users = users.filter((u) => u.role === roleFilter);
  if (status) users = users.filter((u) => u.status === status);
  if (q) {
    const needle = String(q).toLowerCase();
    users = users.filter((u) => (u.name || '').toLowerCase().includes(needle) || (u.email || '').toLowerCase().includes(needle));
  }
  res.json(users.sort((a, b) => b.id - a.id).slice(0, 300).map(({ id, role: userRole, email, phone, name, avatar, status: userStatus, shop_id, permissions, created_at }) =>
    ({ id, role: userRole, email, phone, name, avatar, status: userStatus, shop_id, permissions: JSON.stringify(Array.isArray(permissions) ? permissions : []), created_at })));
});
r.post('/users', perm('admins'), validate(z.object({
  name: z.string().min(2), email: z.string().email().transform((s) => s.toLowerCase()),
  password: z.string().min(12).max(72).regex(/[a-z]/).regex(/[A-Z]/).regex(/\d/),
  role: z.enum(['client', 'shop', 'technician', 'admin']), permissions: z.array(z.enum(PERMS)).optional(),
})), async (req, res) => {
  const b = req.body;
  let id;
  try {
    id = await createAuthUser({
      name: b.name, email: b.email, password: b.password, role: b.role, status: 'active', emailVerified: true,
      permissions: b.role === 'admin' ? b.permissions ?? [] : [],
    });
  } catch (error) {
    if (error.code === 'auth/email-already-exists') return res.status(409).json({ error: 'Email already in use' });
    throw error;
  }
  if (id === null) return res.status(409).json({ error: 'Email already in use' });
  await audit(req, 'admin.user_create', `user:${id}`, { role: b.role });
  res.status(201).json({ id });
});
r.patch('/users/:id', perm('users'), validate(z.object({
  status: z.enum(['active', 'suspended', 'deleted']).optional(), name: z.string().min(2).optional(), reason: z.string().max(300).optional(),
})), async (req, res) => {
  const user = await get('users', req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (user.id === req.user.id) return res.status(400).json({ error: 'You cannot change your own status' });
  if (user.role === 'admin' && !isSuper(req.user)) return res.status(403).json({ error: 'Only a super admin can change admins' });
  if (req.body.status && user.firebase_uid) {
    await firebaseAuth.updateUser(user.firebase_uid, { disabled: req.body.status !== 'active' });
  }
  await update('users', user.id, { ...(req.body.status ? { status: req.body.status } : {}),
    ...(req.body.name ? { name: req.body.name } : {}) });
  if (req.body.status) await notify(user.id, 'Account ' + req.body.status, req.body.reason ?? '');
  await audit(req, 'admin.user_' + (req.body.status ?? 'edit'), `user:${user.id}`, { reason: req.body.reason });
  res.json({ ok: true });
});
r.put('/users/:id/permissions', perm('admins'), validate(z.object({ permissions: z.array(z.enum(PERMS)) })), async (req, res) => {
  if (!isSuper(req.user)) return res.status(403).json({ error: 'Super admin only' });
  const user = await get('users', req.params.id);
  if (!user || user.role !== 'admin') return res.status(404).json({ error: 'Admin account not found' });
  if (isSuper(user)) return res.status(400).json({ error: 'Super admin permissions cannot be changed here' });
  await update('users', user.id, { permissions: req.body.permissions });
  await audit(req, 'admin.permissions', `user:${user.id}`, req.body);
  res.json({ ok: true });
});

r.get('/documents', perm('documents'), async (req, res) => {
  let docs = await list('documents');
  if (req.query.status) docs = docs.filter((d) => d.status === req.query.status);
  const result = await Promise.all(docs.sort((a, b) => b.id - a.id).slice(0, 300).map(async (d) => {
    const [user, profile] = await Promise.all([get('users', d.user_id), get('profiles', d.user_id)]);
    return user && { id: d.id, type: d.type, status: d.status, note: d.note, created_at: d.created_at,
      user_id: user.id, name: user.name, email: user.email, role: user.role, label: profile?.business_name || user.name };
  }));
  res.json(result.filter(Boolean));
});
r.patch('/documents/:id', perm('documents'), validate(z.object({
  status: z.enum(['approved', 'rejected']), note: z.string().max(300).optional(),
})), async (req, res) => {
  const document = await get('documents', req.params.id);
  if (!document) return res.status(404).json({ error: 'Not found' });
  await update('documents', document.id, { status: req.body.status, note: req.body.note ?? null });
  await notify(document.user_id, `Document ${req.body.status}`, req.body.note || `${document.type} was ${req.body.status}.`);
  await audit(req, 'admin.document_' + req.body.status, `document:${document.id}`);
  res.json({ ok: true });
});

const planSchema = z.object({
  name: z.string().min(2), role: z.enum(['shop', 'technician']), price: z.number().min(0),
  interval_days: z.number().int().min(1), commission_pct: z.number().min(0).max(100), active: z.boolean().optional(),
});
r.get('/plans', perm('billing'), async (req, res) => res.json((await list('plans')).sort((a, b) => a.role.localeCompare(b.role) || a.price - b.price)));
r.post('/plans', perm('billing'), validate(planSchema), async (req, res) => {
  const b = req.body;
  await create('plans', { ...b, active: b.active ?? true });
  await audit(req, 'admin.plan_create', b.name);
  res.status(201).json({ ok: true });
});
r.put('/plans/:id', perm('billing'), validate(planSchema.partial()), async (req, res) => {
  if (!await get('plans', req.params.id)) return res.status(404).json({ error: 'Not found' });
  await update('plans', req.params.id, req.body);
  await audit(req, 'admin.plan_update', `plan:${req.params.id}`, req.body);
  res.json({ ok: true });
});
r.get('/subscriptions', perm('billing'), async (req, res) => {
  const [subs, users, plans] = await Promise.all([list('subscriptions'), list('users'), list('plans')]);
  res.json(subs.sort((a, b) => b.id - a.id).slice(0, 300).map((s) => ({
    ...s, name: users.find((u) => u.id === s.user_id)?.name, email: users.find((u) => u.id === s.user_id)?.email,
    plan: plans.find((p) => p.id === s.plan_id)?.name,
  })));
});
r.patch('/subscriptions/:id', perm('billing'), validate(z.object({
  status: z.enum(['active', 'cancelled']).optional(), extendDays: z.number().int().min(1).max(365).optional(),
}).refine((value) => value.status !== undefined || value.extendDays !== undefined, 'Provide a status or extension')), async (req, res) => {
  const current = await get('subscriptions', req.params.id);
  if (!current) return res.status(404).json({ error: 'Subscription not found' });
  const patch = {
    ...(req.body.status ? { status: req.body.status } : {}),
    ...(req.body.extendDays ? {
      status: 'active',
      expires_at: Math.max(current.expires_at, now()) + req.body.extendDays * 86400,
    } : {}),
  };
  await update('subscriptions', current.id, patch);
  await audit(req, 'admin.subscription_edit', `subscription:${current.id}`, req.body);
  res.json({ ok: true });
});

r.get('/settings', perm('settings'), async (req, res) => res.json(Object.fromEntries((await list('settings')).map((x) => [x.key, x.value]))));
r.put('/settings', perm('settings'), validate(z.object({
  platform_fee_pct: z.number().min(0).max(50).optional(), default_commission_pct: z.number().min(0).max(100).optional(),
  maintenance: z.boolean().optional(), terms: z.string().max(20000).optional(),
})), async (req, res) => {
  for (const [key, value] of Object.entries(req.body)) await set('settings', key, {
    key, value: String(typeof value === 'boolean' ? Number(value) : value),
  });
  await audit(req, 'admin.settings', null, req.body);
  res.json({ ok: true });
});

r.get('/categories', perm('content'), async (req, res) => res.json((await list('categories')).sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name))));
r.post('/categories', perm('content'), validate(z.object({ name: z.string().min(2).max(60), kind: z.enum(['device', 'repair']) })), async (req, res) => {
  await create('categories', { ...req.body, active: true });
  res.status(201).json({ ok: true });
});
r.patch('/categories/:id', perm('content'), validate(z.object({ active: z.boolean() })), async (req, res) => {
  if (!await get('categories', req.params.id)) return res.status(404).json({ error: 'Not found' });
  await update('categories', req.params.id, req.body);
  res.json({ ok: true });
});
r.delete('/categories/:id', perm('content'), async (req, res) => {
  await remove('categories', req.params.id);
  res.json({ ok: true });
});
r.post('/announcements', perm('content'), validate(z.object({
  title: z.string().min(2).max(100), body: z.string().min(2).max(1000), audience: z.enum(['all', 'client', 'shop', 'technician']),
})), async (req, res) => {
  const b = req.body;
  await create('announcements', { ...b, created_at: now() });
  const users = (await rowsBy('users', 'status', 'active')).filter((u) => b.audience === 'all' || u.role === b.audience);
  await Promise.all(users.map((u) => notify(u.id, b.title, b.body)));
  await audit(req, 'admin.announcement', b.title);
  res.status(201).json({ ok: true });
});

r.get('/payments', perm('finance'), async (req, res) => {
  const [payments, users] = await Promise.all([list('payments'), list('users')]);
  res.json(payments.sort((a, b) => b.id - a.id).slice(0, 300).map((p) => ({ ...p, payer: users.find((u) => u.id === p.payer_id)?.name })));
});
r.post('/payments/:id/refund', perm('finance'), async (req, res) => {
  const payment = await get('payments', req.params.id);
  if (!payment || payment.status !== 'paid') return res.status(400).json({ error: 'Not refundable' });
  await update('payments', payment.id, { status: 'refunded' });
  if (payment.booking_id) await update('bookings', payment.booking_id, { payment_status: 'refunded' });
  if (payment.subscription_id) await update('subscriptions', payment.subscription_id, { status: 'cancelled' });
  await notify(payment.payer_id, 'Refund processed', `₱${payment.amount}`);
  await audit(req, 'admin.refund', `payment:${payment.id}`, { amount: payment.amount });
  res.json({ ok: true });
});
r.get('/payouts', perm('finance'), async (req, res) => {
  const payments = (await list('payments')).filter((p) => p.kind === 'booking' && p.status === 'paid' && p.payout_status === 'pending');
  const sums = new Map();
  for (const payment of payments) {
    const current = sums.get(payment.provider_id) || { id: payment.provider_id, jobs: 0, owed: 0 };
    current.jobs++;
    current.owed += payment.amount - payment.platform_fee - payment.commission;
    sums.set(payment.provider_id, current);
  }
  const users = await list('users');
  res.json([...sums.values()].map((x) => ({ ...x, name: users.find((u) => u.id === x.id)?.name })));
});
r.post('/payouts/:providerId', perm('finance'), async (req, res) => {
  const payments = (await rowsBy('payments', 'provider_id', +req.params.providerId)).filter((p) => p.kind === 'booking' && p.status === 'paid' && p.payout_status === 'pending');
  await Promise.all(payments.map((p) => update('payments', p.id, { payout_status: 'paid' })));
  await audit(req, 'admin.payout', `user:${req.params.providerId}`, { payments: payments.length });
  res.json({ paidOut: payments.length });
});
r.get('/reports/financial', perm('finance'), async (req, res) => {
  const from = +req.query.from || 0, to = +req.query.to || now();
  const payments = (await list('payments')).filter((p) => p.created_at >= from && p.created_at <= to);
  res.json({
    booking_volume: payments.filter((p) => p.kind === 'booking' && p.status === 'paid').reduce((s, p) => s + p.amount, 0),
    commissions: payments.filter((p) => p.kind === 'booking' && p.status === 'paid').reduce((s, p) => s + p.commission, 0),
    platform_fees: payments.filter((p) => p.kind === 'booking' && p.status === 'paid').reduce((s, p) => s + p.platform_fee, 0),
    subscriptions: payments.filter((p) => p.kind === 'subscription' && p.status === 'paid').reduce((s, p) => s + p.amount, 0),
    refunds: payments.filter((p) => p.status === 'refunded').reduce((s, p) => s + p.amount, 0),
  });
});
r.get('/disputes', perm('reports'), async (req, res) => {
  const [reports, users] = await Promise.all([list('reports'), list('users')]);
  res.json(reports.sort((a, b) => Number(['open', 'appeal'].includes(b.status)) - Number(['open', 'appeal'].includes(a.status)) || b.id - a.id)
    .slice(0, 300).map((d) => ({ ...d, reporter: users.find((u) => u.id === d.reporter_id)?.name, target: users.find((u) => u.id === d.target_id)?.name })));
});
r.patch('/disputes/:id', perm('reports'), validate(z.object({
  status: z.enum(['resolved', 'dismissed']), resolution: z.string().max(500), suspendTarget: z.boolean().optional(),
})), async (req, res) => {
  const report = await get('reports', req.params.id);
  if (!report) return res.status(404).json({ error: 'Not found' });
  await update('reports', report.id, { status: req.body.status, resolution: req.body.resolution });
  if (req.body.suspendTarget) {
    const target = await get('users', report.target_id);
    if (target && target.role !== 'admin') {
      if (target.firebase_uid) await firebaseAuth.updateUser(target.firebase_uid, { disabled: true });
      await update('users', target.id, { status: 'suspended' });
      await notify(target.id, 'Account suspended', req.body.resolution + ' You can appeal from the Reports page.');
    }
  }
  await notify(report.reporter_id, 'Report ' + req.body.status, req.body.resolution);
  await audit(req, 'admin.dispute_' + req.body.status, `report:${report.id}`);
  res.json({ ok: true });
});
r.get('/audit', perm('reports'), async (req, res) => {
  const [logs, users] = await Promise.all([list('audit_logs'), list('users')]);
  res.json(logs.sort((a, b) => b.id - a.id).slice(0, 300).map((x) => ({ ...x, actor: users.find((u) => u.id === x.actor_id)?.name })));
});
r.get('/security-alerts', perm('reports'), async (req, res) => {
  const [logs, users] = await Promise.all([list('audit_logs'), list('users')]);
  res.json(logs.filter((x) => x.action.startsWith('security.')).sort((a, b) => b.id - a.id).slice(0, 100)
    .map((x) => ({ ...x, email: users.find((u) => u.id === x.actor_id)?.email })));
});

export default r;
