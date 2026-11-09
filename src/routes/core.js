import { Router } from 'express';
import multer from 'multer';
import path from 'path';
import { z } from 'zod';
import { auth as firebaseAuth, completeBookingWithPayment, create, createAuthUser, createUnique, deleteUpload, get, list, MAX_UPLOAD_BYTES, remove, saveUpload, setting, streamUpload, update, updateMany } from '../db.js';
import { auth, role, validate, audit, notify } from '../mw.js';

const r = Router();
const now = () => Math.floor(Date.now() / 1000);
const uploader = (types) => multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
  fileFilter: (q, f, cb) => (types.includes(f.mimetype) ? cb(null, true) : cb(new Error('File type not allowed'))),
});
const IMG = ['image/jpeg', 'image/png', 'image/webp'];
const pub = uploader(IMG), priv = uploader([...IMG, 'application/pdf']);
const isProvider = (u) => u.role === 'shop' || u.role === 'technician';
const ownerOf = (u) => (u.role === 'technician' && u.shop_id ? u.shop_id : u.id);
const by = (collection, field, value, options = {}) => list(collection, { where: [[field, '==', value]], ...options });
const asArray = (value) => Array.isArray(value) ? value : [];
const byId = (rows, id) => rows.find((row) => row.id === id);

async function activeSub(uid) {
  const rows = await by('subscriptions', 'user_id', uid);
  const subscriptions = rows.filter((s) => s.status === 'active' && s.expires_at > now()).sort((a, b) => b.expires_at - a.expires_at);
  if (!subscriptions.length) return null;
  const plan = await get('plans', subscriptions[0].plan_id);
  return { ...subscriptions[0], commission_pct: plan?.commission_pct };
}
async function approved(uid) {
  return (await by('documents', 'user_id', uid)).some((d) => d.status === 'approved');
}
async function userProfile(id) {
  return await get('profiles', id) || { user_id: id, gallery: [], working_hours: {} };
}
async function enrichBooking(booking) {
  const [client, provider, profile, technician, reviews] = await Promise.all([
    get('users', booking.client_id), get('users', booking.provider_id), get('profiles', booking.provider_id),
    booking.technician_id ? get('users', booking.technician_id) : null,
    by('reviews', 'booking_id', booking.id),
  ]);
  return {
    ...booking, client_name: client?.name, client_phone: client?.phone, provider_name: provider?.name,
    provider_label: profile?.business_name || provider?.name, technician_name: technician?.name,
    reviewed: reviews.length ? 1 : null, photos: asArray(booking.photos), parts: asArray(booking.parts), progress: asArray(booking.progress),
  };
}
const canSee = (u, b) => u.role === 'admin' || b.client_id === u.id || b.provider_id === u.id || b.technician_id === u.id;

r.post('/uploads/photo', auth, pub.single('file'), async (req, res) => {
  const filename = await saveUpload('public', req.file);
  res.json({ url: `/uploads/public/${filename}` });
});

const profileSchema = z.object({
  name: z.string().min(2).max(80).optional(), phone: z.string().max(20).optional(),
  business_name: z.string().max(100).optional(), bio: z.string().max(1000).optional(), address: z.string().max(200).optional(),
  city: z.string().max(80).optional(), lat: z.number().min(-90).max(90).nullable().optional(), lng: z.number().min(-180).max(180).nullable().optional(),
  specialties: z.string().max(300).optional(), supported_devices: z.string().max(300).optional(),
  service_radius_km: z.number().min(0).max(500).optional(), capacity: z.number().int().min(1).max(200).optional(),
  service_areas: z.string().max(300).optional(), warranty_terms: z.string().max(500).optional(),
  working_hours: z.record(z.array(z.string()).length(2)).optional(),
});
r.get('/profile', auth, async (req, res) => {
  const p = await userProfile(req.user.id);
  const docs = (await by('documents', 'user_id', req.user.id)).map(({ id, type, status, note, created_at }) => ({ id, type, status, note, created_at }));
  res.json({ ...p, name: req.user.name, phone: req.user.phone, email: req.user.email, avatar: req.user.avatar, role: req.user.role,
    working_hours: p.working_hours || {}, gallery: asArray(p.gallery), documents: docs, approved: await approved(req.user.id) });
});
r.put('/profile', auth, validate(profileSchema), async (req, res) => {
  const { name, phone, ...profile } = req.body;
  const userPatch = {};
  if (name !== undefined) userPatch.name = name;
  if (phone !== undefined) userPatch.phone = phone;
  if (Object.keys(userPatch).length) await update('users', req.user.id, userPatch);
  if (Object.keys(profile).length) await update('profiles', req.user.id, profile);
  await audit(req, 'profile.update', `user:${req.user.id}`);
  res.json({ ok: true });
});
r.post('/profile/avatar', auth, pub.single('file'), async (req, res) => {
  const avatar = `/uploads/public/${await saveUpload('public', req.file)}`;
  await update('users', req.user.id, { avatar });
  res.json({ avatar });
});
r.post('/profile/gallery', auth, role('shop', 'technician'), pub.single('file'), async (req, res) => {
  const p = await userProfile(req.user.id), gallery = asArray(p.gallery);
  if (gallery.length >= 12) return res.status(400).json({ error: 'Gallery is full (12 images)' });
  gallery.push(`/uploads/public/${await saveUpload('public', req.file)}`);
  await update('profiles', req.user.id, { gallery });
  res.json({ gallery });
});
r.delete('/profile/gallery', auth, role('shop', 'technician'), async (req, res) => {
  const p = await userProfile(req.user.id);
  const url = String(req.query.url || '');
  const filename = /^\/uploads\/public\/([\w-]+\.(jpg|png|webp))$/.exec(url)?.[1];
  if (asArray(p.gallery).includes(url)) {
    if (filename) await deleteUpload(`public/${filename}`);
    await update('profiles', req.user.id, { gallery: asArray(p.gallery).filter((x) => x !== url) });
  }
  res.json({ ok: true });
});

r.post('/documents', auth, role('shop', 'technician'), priv.single('file'), async (req, res) => {
  const type = z.string().min(2).max(60).parse(req.body.type || 'permit');
  const filename = await saveUpload('private', req.file);
  await create('documents', { user_id: req.user.id, type, file: filename, status: 'pending', note: null, created_at: now() });
  await notify(req.user.id, 'Document submitted', `${type} is waiting for administrator review.`);
  res.status(201).json({ ok: true });
});
r.get('/documents/:id/file', auth, async (req, res) => {
  const d = await get('documents', req.params.id);
  if (!d || (d.user_id !== req.user.id && req.user.role !== 'admin')) return res.status(404).end();
  await streamUpload(`private/${path.basename(d.file)}`, res, true);
});
r.delete('/documents/:id', auth, role('shop', 'technician'), async (req, res) => {
  const d = await get('documents', req.params.id);
  if (d?.user_id === req.user.id && d.status !== 'approved') {
    await deleteUpload(`private/${path.basename(d.file)}`);
    await remove('documents', d.id);
  }
  res.json({ ok: true });
});

r.get('/categories', async (req, res) => res.json((await list('categories')).filter((x) => x.active).sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name))));
const km = (a, b, c, d) => { const R = 6371, t = Math.PI / 180, x = (c - a) * t, y = (d - b) * t; const h = Math.sin(x / 2) ** 2 + Math.cos(a * t) * Math.cos(c * t) * Math.sin(y / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(h)); };
r.get('/providers', auth, async (req, res) => {
  const { q, type, device, repair, city, minPrice, maxPrice, minRating, date, lat, lng } = req.query;
  const [users, profiles, docs, services, reviews, bookings] = await Promise.all([
    by('users', 'status', 'active'), list('profiles'), list('documents'), list('services'), list('reviews'), list('bookings'),
  ]);
  const like = (s, t) => (s || '').toLowerCase().includes(String(t).toLowerCase());
  const publicProviders = users.filter((u) => isProvider(u) && !u.shop_id
    && docs.some((d) => d.user_id === u.id && d.status === 'approved'));
  const providerRows = publicProviders.map((u) => {
    const p = byId(profiles, u.id) || {};
    const providerServices = services.filter((s) => s.provider_id === u.id && s.active);
    const providerReviews = reviews.filter((review) => review.provider_id === u.id);
    return { id: u.id, provider_id: u.id, technician_id: null, role: u.role, name: u.name, avatar: u.avatar, business_name: p.business_name, city: p.city,
      address: p.address, lat: p.lat, lng: p.lng, specialties: p.specialties, supported_devices: p.supported_devices,
      service_radius_km: p.service_radius_km, working_hours: p.working_hours || {}, capacity: p.capacity || 5,
      rating: providerReviews.length ? providerReviews.reduce((sum, review) => sum + review.rating, 0) / providerReviews.length : null,
      reviews: providerReviews.length, min_price: providerServices.length ? Math.min(...providerServices.map((s) => s.price)) : null,
      providerServices };
  });
  const shopRows = providerRows.filter((x) => x.role === 'shop');
  const staffRows = users.filter((u) => u.role === 'technician' && u.shop_id && u.status === 'active')
    .map((technician) => {
      const shop = byId(publicProviders, technician.shop_id);
      if (!shop) return null;
      const profile = byId(profiles, technician.id) || {};
      const shopProfile = byId(profiles, shop.id) || {};
      const providerServices = services.filter((s) => s.provider_id === shop.id && s.active);
      const providerReviews = reviews.filter((review) => review.provider_id === shop.id);
      return {
        id: technician.id, provider_id: shop.id, technician_id: technician.id, role: 'technician',
        name: technician.name, avatar: technician.avatar || shop.avatar, business_name: shopProfile.business_name || shop.name,
        city: shopProfile.city, address: shopProfile.address, lat: shopProfile.lat, lng: shopProfile.lng,
        specialties: profile.specialties || shopProfile.specialties, supported_devices: shopProfile.supported_devices,
        service_radius_km: shopProfile.service_radius_km, working_hours: shopProfile.working_hours || {},
        capacity: shopProfile.capacity || 5,
        rating: providerReviews.length ? providerReviews.reduce((sum, review) => sum + review.rating, 0) / providerReviews.length : null,
        reviews: providerReviews.length, min_price: providerServices.length ? Math.min(...providerServices.map((s) => s.price)) : null,
        providerServices,
      };
    }).filter(Boolean);
  const candidates = type === 'shop'
    ? shopRows
    : type === 'technician'
      ? [...providerRows.filter((x) => x.role === 'technician'), ...staffRows]
      : providerRows.filter((x) => x.role === 'shop' || x.role === 'technician').concat(staffRows);
  const rows = candidates.filter((x) => {
    if (type && x.role !== type) return false;
    if (city && !like(x.city, city)) return false;
    if (device && !like(x.supported_devices, device) && !x.providerServices.some((s) => like(s.device, device))) return false;
    if (repair && !like(x.specialties, repair) && !x.providerServices.some((s) => like(s.repair_type, repair) || like(s.title, repair))) return false;
    if (q && ![x.name, x.business_name, x.specialties, x.supported_devices].some((f) => like(f, q))) return false;
    if (minRating && (x.rating || 0) < +minRating) return false;
    if (minPrice && (x.min_price ?? Infinity) < +minPrice) return false;
    if (maxPrice && (x.min_price ?? Infinity) > +maxPrice) return false;
    if (date) {
      const weekday = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'][new Date(date + 'T12:00:00').getDay()];
      if (!x.working_hours[weekday]) return false;
      const start = Math.floor(new Date(date + 'T00:00:00').getTime() / 1000);
      const busy = bookings.filter((b) => (x.technician_id ? b.technician_id === x.technician_id : b.provider_id === x.provider_id)
        && b.scheduled_at >= start && b.scheduled_at <= start + 86399
        && ['requested', 'accepted', 'in_progress'].includes(b.status)).length;
      if (busy >= x.capacity) return false;
    }
    return true;
  }).map((x) => ({ ...x, providerServices: undefined, rating: x.rating ? +x.rating.toFixed(1) : null,
    distance_km: lat && lng && x.lat != null ? +km(+lat, +lng, x.lat, x.lng).toFixed(1) : null }));
  rows.sort((a, b) => (a.distance_km ?? 1e9) - (b.distance_km ?? 1e9) || (b.rating || 0) - (a.rating || 0));
  res.json(rows);
});
r.get('/providers/:id', auth, async (req, res) => {
  const requested = await get('users', req.params.id);
  const technician = requested?.shop_id ? requested : null;
  const u = technician ? await get('users', technician.shop_id) : requested;
  if (!u || u.status !== 'active' || !isProvider(u) || u.shop_id || !await approved(u.id)
    || (technician && (technician.status !== 'active' || technician.role !== 'technician'))) {
    return res.status(404).json({ error: 'Provider not found' });
  }
  const p = await userProfile(u.id);
  const [services, staff, reviews] = await Promise.all([by('services', 'provider_id', u.id), by('users', 'shop_id', u.id), by('reviews', 'provider_id', u.id)]);
  const technicians = await Promise.all(staff.filter((x) => x.status === 'active').map(async (x) => {
    const profile = await userProfile(x.id);
    return { id: x.id, name: x.name, avatar: x.avatar, specialties: profile.specialties };
  }));
  const reviewRows = await Promise.all(reviews.sort((a, b) => b.id - a.id).slice(0, 30).map(async (x) => ({ ...x, client: (await get('users', x.client_id))?.name })));
  const technicianProfile = technician ? await userProfile(technician.id) : null;
  res.json({ id: u.id, role: technician ? 'technician' : u.role,
    name: technician?.name || u.name, avatar: technician?.avatar || u.avatar, ...p,
    ...(technician ? { technicianId: technician.id, technicianSpecialties: technicianProfile.specialties } : {}),
    working_hours: p.working_hours || {}, gallery: asArray(p.gallery),
    services: services.filter((x) => x.active), technicians: u.role === 'shop' ? technicians : [],
    reviews: reviewRows, verified: true });
});

const svc = z.object({ title: z.string().min(2).max(100), device: z.string().max(60).optional(), repair_type: z.string().max(60).optional(), price: z.number().min(0).max(1e6), duration_min: z.number().int().min(5).max(10080).optional(), active: z.boolean().optional() });
r.get('/services', auth, role('shop', 'technician'), async (req, res) => res.json(await by('services', 'provider_id', ownerOf(req.user))));
r.post('/services', auth, role('shop', 'technician'), validate(svc), async (req, res) => {
  if (req.user.shop_id) return res.status(403).json({ error: 'Only the shop owner manages the catalog' });
  const b = req.body;
  await create('services', { provider_id: req.user.id, title: b.title, device: b.device ?? null, repair_type: b.repair_type ?? null, price: b.price, duration_min: b.duration_min ?? 60, active: true });
  res.status(201).json({ ok: true });
});
r.put('/services/:id', auth, role('shop', 'technician'), validate(svc.partial()), async (req, res) => {
  const service = await get('services', req.params.id);
  if (service?.provider_id === req.user.id) await update('services', service.id, req.body);
  res.json({ ok: true });
});
r.delete('/services/:id', auth, role('shop', 'technician'), async (req, res) => {
  const service = await get('services', req.params.id);
  if (service?.provider_id === req.user.id) await remove('services', service.id);
  res.json({ ok: true });
});

r.get('/staff', auth, role('shop'), async (req, res) => {
  const users = await by('users', 'shop_id', req.user.id);
  res.json(await Promise.all(users.map(async (u) => ({ id: u.id, name: u.name, email: u.email, status: u.status, avatar: u.avatar, specialties: (await userProfile(u.id)).specialties }))));
});
r.post('/staff', auth, role('shop'), validate(z.object({ name: z.string().min(2).max(80), email: z.string().email().transform((s) => s.toLowerCase()), password: z.string().min(10).max(72).regex(/[a-z]/).regex(/[A-Z]/).regex(/\d/), specialties: z.string().max(300).optional() })), async (req, res) => {
  const b = req.body;
  let id;
  try {
    id = await createAuthUser({ role: 'technician', email: b.email, password: b.password, name: b.name, status: 'active', emailVerified: true, shop_id: req.user.id, permissions: [] }, { specialties: b.specialties ?? '' });
  } catch (error) {
    if (error.code === 'auth/email-already-exists') return res.status(409).json({ error: 'Email already in use' });
    throw error;
  }
  if (id === null) return res.status(409).json({ error: 'Email already in use' });
  await audit(req, 'staff.create', `user:${id}`);
  res.status(201).json({ ok: true });
});
r.patch('/staff/:id', auth, role('shop'), validate(z.object({ status: z.enum(['active', 'suspended']) })), async (req, res) => {
  const user = await get('users', req.params.id);
  if (user?.shop_id === req.user.id) {
    if (user.firebase_uid) await firebaseAuth.updateUser(user.firebase_uid, { disabled: req.body.status !== 'active' });
    await update('users', user.id, { status: req.body.status });
  }
  res.json({ ok: true });
});

r.get('/bookings', auth, async (req, res) => {
  const u = req.user;
  const field = u.role === 'client' ? 'client_id' : u.role === 'technician' && u.shop_id ? 'technician_id' : 'provider_id';
  let bookings = u.role === 'admin' ? await list('bookings') : await by('bookings', field, u.id);
  if (req.query.status) bookings = bookings.filter((b) => b.status === req.query.status);
  bookings.sort((a, b) => b.scheduled_at - a.scheduled_at);
  res.json(await Promise.all(bookings.slice(0, 300).map(enrichBooking)));
});
r.get('/bookings/:id', auth, async (req, res) => {
  const b = await get('bookings', req.params.id);
  if (!b || !canSee(req.user, b)) return res.status(404).json({ error: 'Not found' });
  res.json(await enrichBooking(b));
});
r.post('/bookings', auth, role('client'), validate(z.object({
  providerId: z.number().int(), technicianId: z.number().int().optional(), serviceId: z.number().int().optional(),
  device: z.string().min(2).max(80), issue: z.string().min(5).max(1000), scheduledAt: z.number().int(), photos: z.array(z.string().regex(/^\/uploads\/public\/[\w-]+\.(jpg|png|webp)$/)).max(6).optional(),
})), async (req, res) => {
  const b = req.body;
  if (await setting('maintenance', '0') === '1') return res.status(503).json({ error: 'Platform is under maintenance' });
  const provider = await get('users', b.providerId);
  if (!provider || provider.status !== 'active' || !isProvider(provider) || provider.shop_id || !await approved(provider.id)) return res.status(400).json({ error: 'Provider is not available' });
  if (!await activeSub(provider.id)) return res.status(400).json({ error: 'This provider is not accepting bookings right now' });
  if (b.scheduledAt < now()) return res.status(400).json({ error: 'Pick a future time' });
  if (b.technicianId) {
    const tech = await get('users', b.technicianId);
    if (!tech || tech.shop_id !== provider.id || tech.status !== 'active') return res.status(400).json({ error: 'Technician does not work at this shop' });
  }
  const profile = await userProfile(provider.id);
  const start = Math.floor(b.scheduledAt / 86400) * 86400;
  const daily = (await by('bookings', 'provider_id', provider.id)).filter((x) => x.scheduled_at >= start && x.scheduled_at <= start + 86399 && ['requested', 'accepted', 'in_progress'].includes(x.status));
  if (daily.length >= (profile.capacity || 5)) return res.status(400).json({ error: 'Fully booked that day' });
  let estimate = null;
  if (b.serviceId) {
    const service = await get('services', b.serviceId);
    if (service?.provider_id === provider.id) estimate = service.price;
  }
  const id = await create('bookings', {
    client_id: req.user.id, provider_id: provider.id, technician_id: b.technicianId ?? null, service_id: b.serviceId ?? null,
    device: b.device, issue: b.issue, photos: b.photos ?? [], scheduled_at: b.scheduledAt, status: 'requested',
    estimate, parts: [], result: null, warranty_days: 0, warranty_until: null, total: null, payment_status: 'unpaid',
    progress: [], created_at: now(), updated_at: now(),
  });
  await notify(provider.id, 'New booking request', `${req.user.name}: ${b.device}`);
  if (b.technicianId) await notify(b.technicianId, 'New job requested for you', b.device);
  res.status(201).json({ id });
});

const actionSchema = z.object({
  action: z.enum(['accept', 'reject', 'reschedule', 'assign', 'start', 'update', 'complete', 'cancel']),
  scheduledAt: z.number().int().optional(), technicianId: z.number().int().nullable().optional(),
  estimate: z.number().min(0).optional(), parts: z.array(z.object({ name: z.string().max(80), cost: z.number().min(0) })).max(30).optional(),
  note: z.string().max(500).optional(), result: z.string().max(1000).optional(),
  warrantyDays: z.number().int().min(0).max(1095).optional(), total: z.number().min(0).max(1e6).optional(),
});
r.post('/bookings/:id/action', auth, validate(actionSchema), async (req, res) => {
  const u = req.user, b = await get('bookings', req.params.id), a = req.body;
  if (!b || !canSee(u, b)) return res.status(404).json({ error: 'Not found' });
  const isOwner = b.provider_id === u.id, isAssigned = b.technician_id === u.id, isClient = b.client_id === u.id;
  const fail = (message, code = 400) => res.status(code).json({ error: message });
  const progress = (text) => [...asArray(b.progress), { t: now(), text }];
  const save = async (patch) => update('bookings', b.id, { ...patch, updated_at: now() });
  switch (a.action) {
    case 'accept':
      if (!isOwner) return fail('Only the provider can do that', 403);
      if (b.status !== 'requested') return fail('Already handled');
      if (!await activeSub(u.id)) return fail('Subscribe to accept bookings');
      await save({ status: 'accepted', progress: progress('Booking accepted') });
      await notify(b.client_id, 'Booking accepted', 'Your repair request was accepted.');
      break;
    case 'reject':
      if (!isOwner) return fail('Only the provider can do that', 403);
      if (!['requested', 'accepted'].includes(b.status)) return fail('Cannot reject now');
      await save({ status: 'rejected', progress: progress('Rejected' + (a.note ? ': ' + a.note : '')) });
      await notify(b.client_id, 'Booking declined', a.note || 'The provider cannot take this job.');
      break;
    case 'reschedule':
      if (!isOwner) return fail('Only the provider can do that', 403);
      if (!a.scheduledAt || a.scheduledAt < now()) return fail('Pick a future time');
      await save({ scheduled_at: a.scheduledAt, progress: progress('Rescheduled') });
      await notify(b.client_id, 'Booking rescheduled', 'The provider proposed a new time. Open your booking.');
      break;
    case 'assign':
      if (!isOwner) return fail('Only the provider can do that', 403);
      if (u.role !== 'shop') return fail('Only shops assign staff');
      if (a.technicianId) {
        const technician = await get('users', a.technicianId);
        if (!technician || technician.shop_id !== u.id || technician.status !== 'active') return fail('Not your staff');
      }
      await save({ technician_id: a.technicianId ?? null, progress: progress('Technician assigned') });
      if (a.technicianId) await notify(a.technicianId, 'Job assigned to you', `Booking #${b.id}`);
      break;
    case 'start':
      if (!(isOwner || isAssigned)) return fail('Not allowed', 403);
      if (b.status !== 'accepted') return fail('Booking must be accepted first');
      await save({ status: 'in_progress', progress: progress('Repair started') });
      await notify(b.client_id, 'Repair started', `Booking #${b.id} is in progress.`);
      break;
    case 'update':
      if (!(isOwner || isAssigned)) return fail('Not allowed', 403);
      if (!['accepted', 'in_progress'].includes(b.status)) return fail('Booking is closed');
      await save({ ...(a.estimate !== undefined ? { estimate: a.estimate } : {}),
        ...(a.parts ? { parts: a.parts } : {}), progress: progress(a.note || 'Estimate updated') });
      await notify(b.client_id, 'Repair update', a.note || 'The estimate or parts were updated.');
      break;
    case 'complete': {
      if (!(isOwner || isAssigned)) return fail('Not allowed', 403);
      if (b.status !== 'in_progress') return fail('Start the repair first');
      const total = a.total ?? b.estimate;
      if (total == null) return fail('Enter the final total');
      const days = a.warrantyDays ?? 0;
      const sub = await activeSub(b.provider_id);
      const pct = sub?.commission_pct ?? +(await setting('default_commission_pct', '10'));
      const feePct = +(await setting('platform_fee_pct', '2'));
      const fee = +(total * feePct / 100).toFixed(2);
      const completedAt = now();
      const recorded = await completeBookingWithPayment(b.id, {
        status: 'completed', total, result: a.result ?? null, warranty_days: days,
        warranty_until: days ? completedAt + days * 86400 : null, progress: progress('Repair completed'),
      }, {
        kind: 'booking', booking_id: b.id, payer_id: b.client_id, provider_id: b.provider_id,
        amount: total + fee, platform_fee: fee, commission: +(total * pct / 100).toFixed(2),
        status: 'paid', payment_mode: 'demo', payout_status: 'pending', created_at: completedAt,
      });
      if (!recorded) return fail('This booking is no longer in progress');
      await notify(b.client_id, 'Repair completed', `Total ₱${total} recorded as paid. This is a demo record; no real payment was charged. You can now rate the service.`);
      break;
    }
    case 'cancel':
      if (!isClient) return fail('Only the client can cancel', 403);
      if (!['requested', 'accepted'].includes(b.status)) return fail('Too late to cancel');
      await save({ status: 'cancelled', progress: progress('Cancelled by client') });
      await notify(b.provider_id, 'Booking cancelled', `Booking #${b.id}`);
      break;
  }
  await audit(req, 'booking.' + a.action, `booking:${b.id}`);
  res.json(await enrichBooking({ ...b, ...await get('bookings', b.id) }));
});

r.get('/messages/threads', auth, async (req, res) => {
  const id = req.user.id, messages = await list('messages');
  const latest = new Map();
  for (const m of messages) {
    const other = m.sender_id === id ? m.receiver_id : m.receiver_id === id ? m.sender_id : null;
    if (other !== null && (!latest.has(other) || latest.get(other).id < m.id)) latest.set(other, m);
  }
  const threads = await Promise.all([...latest.entries()].map(async ([other, message]) => {
    const user = await get('users', other);
    if (!user) return null;
    return { id: user.id, name: user.name, avatar: user.avatar, role: user.role, last: message.body, at: message.created_at,
      unread: messages.filter((m) => m.sender_id === other && m.receiver_id === id && !m.read).length };
  }));
  res.json(threads.filter(Boolean).sort((a, b) => b.at - a.at));
});
r.get('/messages/:uid', auth, async (req, res) => {
  const me = req.user.id, other = +req.params.uid;
  const conversation = (await list('messages')).filter((m) => (m.sender_id === me && m.receiver_id === other) || (m.sender_id === other && m.receiver_id === me)).sort((a, b) => a.id - b.id);
  await Promise.all(conversation.filter((m) => m.sender_id === other && m.receiver_id === me && !m.read).map((m) => update('messages', m.id, { read: true })));
  const user = await get('users', other);
  res.json({ with: user ? { id: user.id, name: user.name, avatar: user.avatar, role: user.role } : null, messages: conversation.slice(-500) });
});
r.post('/messages', auth, validate(z.object({ to: z.number().int(), body: z.string().min(1).max(2000), bookingId: z.number().int().optional() })), async (req, res) => {
  const to = await get('users', req.body.to), me = req.user;
  if (!to || to.status !== 'active' || to.id === me.id) return res.status(400).json({ error: 'Recipient not available' });
  const pair = [me.role, to.role], allowed = pair.includes('admin') || (pair.includes('client') && pair.some((roleName) => roleName === 'shop' || roleName === 'technician'));
  if (!allowed) return res.status(403).json({ error: 'You can only chat between clients and providers' });
  await create('messages', { sender_id: me.id, receiver_id: to.id, booking_id: req.body.bookingId ?? null, body: req.body.body, read: false, created_at: now() });
  await notify(to.id, 'New message', `${me.name}: ${req.body.body.slice(0, 80)}`);
  res.status(201).json({ ok: true });
});

r.get('/notifications', auth, async (req, res) => {
  const rows = await by('notifications', 'user_id', req.user.id);
  res.json(rows.sort((a, b) => b.id - a.id).slice(0, 100));
});
r.post('/notifications/read', auth, async (req, res) => {
  await updateMany('notifications', [['user_id', '==', req.user.id]], { read: true });
  res.json({ ok: true });
});
r.patch('/notifications/:id', auth, validate(z.object({ read: z.boolean() })), async (req, res) => {
  const notification = await get('notifications', req.params.id);
  if (!notification || notification.user_id !== req.user.id) return res.status(404).json({ error: 'Notification not found' });
  await update('notifications', notification.id, { read: req.body.read });
  res.json({ ok: true });
});
r.post('/reviews', auth, role('client'), validate(z.object({ bookingId: z.number().int(), rating: z.number().int().min(1).max(5), comment: z.string().max(1000).optional() })), async (req, res) => {
  const booking = await get('bookings', req.body.bookingId);
  if (!booking || booking.client_id !== req.user.id || booking.status !== 'completed') return res.status(400).json({ error: 'Only completed bookings can be rated' });
  const reviewId = await createUnique('reviews', 'booking_id', booking.id, {
    booking_id: booking.id, client_id: req.user.id, provider_id: booking.provider_id,
    rating: req.body.rating, comment: req.body.comment ?? null, created_at: now(),
  });
  if (reviewId === null) return res.status(409).json({ error: 'Already rated' });
  await notify(booking.provider_id, 'New review', `${req.body.rating}★ from ${req.user.name}`);
  res.status(201).json({ ok: true });
});
r.post('/reports', auth, validate(z.object({ targetId: z.number().int(), bookingId: z.number().int().optional(), reason: z.string().min(5).max(1000) })), async (req, res) => {
  await create('reports', { reporter_id: req.user.id, target_id: req.body.targetId, booking_id: req.body.bookingId ?? null, reason: req.body.reason, status: 'open', created_at: now() });
  res.status(201).json({ ok: true });
});
r.get('/reports/mine', auth, async (req, res) => res.json((await list('reports')).filter((x) => x.reporter_id === req.user.id || x.target_id === req.user.id).sort((a, b) => b.id - a.id)));
r.post('/reports/:id/appeal', auth, validate(z.object({ text: z.string().min(5).max(1000) })), async (req, res) => {
  const report = await get('reports', req.params.id);
  if (report?.target_id === req.user.id && report.status === 'resolved') await update('reports', report.id, { status: 'appeal', appeal_text: req.body.text });
  res.json({ ok: true });
});

r.get('/plans', auth, role('shop', 'technician'), async (req, res) => res.json((await by('plans', 'role', req.user.role)).filter((p) => p.active)));
r.get('/subscription', auth, role('shop', 'technician'), async (req, res) => res.json(await activeSub(ownerOf(req.user))));
r.post('/subscribe', auth, role('shop', 'technician'), validate(z.object({ planId: z.number().int() })), async (req, res) => {
  if (req.user.shop_id) return res.status(403).json({ error: 'Owner only' });
  const plan = await get('plans', req.body.planId);
  if (!plan || plan.role !== req.user.role || !plan.active) return res.status(400).json({ error: 'Plan not available' });
  const cur = await activeSub(req.user.id), start = cur ? cur.expires_at : now();
  const subscriptions = await by('subscriptions', 'user_id', req.user.id);
  await Promise.all(subscriptions.filter((s) => s.status === 'active').map((s) => update('subscriptions', s.id, { status: 'replaced' })));
  const subscriptionId = await create('subscriptions', { user_id: req.user.id, plan_id: plan.id, status: 'active', started_at: now(), expires_at: start + plan.interval_days * 86400 });
  await create('payments', { kind: 'subscription', subscription_id: subscriptionId, payer_id: req.user.id, amount: plan.price, status: 'paid', payment_mode: 'demo', payout_status: 'pending', created_at: now() });
  await notify(req.user.id, 'Subscription active', plan.name);
  await audit(req, 'subscription.buy', `plan:${plan.id}`);
  res.json({ ok: true });
});
r.get('/earnings', auth, role('shop', 'technician'), async (req, res) => {
  const providerId = ownerOf(req.user);
  const bookingsBeforeSync = await by('bookings', 'provider_id', providerId);
  const completedWithoutPayment = bookingsBeforeSync.filter((booking) => booking.status === 'completed'
    && booking.payment_status !== 'refunded' && Number.isFinite(booking.total));
  let commissionPct, feePct;
  if (completedWithoutPayment.length) {
    const sub = await activeSub(providerId);
    commissionPct = sub?.commission_pct ?? +(await setting('default_commission_pct', '10'));
    feePct = +(await setting('platform_fee_pct', '2'));
  }
  await Promise.all(completedWithoutPayment.map(async (booking) => {
    const platformFee = +(booking.total * feePct / 100).toFixed(2);
    const completedAt = booking.updated_at || booking.created_at || now();
    await completeBookingWithPayment(booking.id, {}, {
      kind: 'booking', booking_id: booking.id, payer_id: booking.client_id, provider_id: providerId,
      amount: booking.total + platformFee, platform_fee: platformFee,
      commission: +(booking.total * commissionPct / 100).toFixed(2),
      status: 'paid', payment_mode: 'demo', payout_status: 'pending', created_at: completedAt,
    });
  }));
  const [rows, allBookings] = await Promise.all([
    by('payments', 'provider_id', providerId),
    list('bookings'),
  ]);
  const bookings = allBookings.filter((booking) => booking.provider_id === providerId
    && booking.status === 'completed' && booking.payment_status !== 'refunded'
    && Number.isFinite(booking.total));
  const bookingPayments = new Map(rows.filter((payment) => payment.kind === 'booking')
    .map((payment) => [payment.booking_id, payment]));
  const needsCalculatedPayment = bookings.some((booking) => !bookingPayments.has(booking.id));
  if (needsCalculatedPayment && commissionPct === undefined) {
    const sub = await activeSub(providerId);
    commissionPct = sub?.commission_pct ?? +(await setting('default_commission_pct', '10'));
    feePct = +(await setting('platform_fee_pct', '2'));
  }
  const payments = bookings.flatMap((booking) => {
    const payment = bookingPayments.get(booking.id);
    if (payment?.status === 'refunded') return [];
    if (payment) return [{ ...payment, device: booking.device }];
    const platformFee = +(booking.total * feePct / 100).toFixed(2);
    return [{
      id: `booking-${booking.id}`, booking_id: booking.id, device: booking.device,
      amount: booking.total + platformFee, platform_fee: platformFee,
      commission: +(booking.total * commissionPct / 100).toFixed(2),
      status: 'paid', payout_status: 'pending', created_at: booking.updated_at || booking.created_at || now(),
    }];
  }).sort((a, b) => b.created_at - a.created_at);
  const gross = payments.reduce((sum, payment) => sum + payment.amount - payment.platform_fee, 0);
  const commission = payments.reduce((sum, payment) => sum + payment.commission, 0);
  const awaitingPayment = allBookings
    .filter((b) => b.provider_id === ownerOf(req.user) && b.status === 'completed' && b.payment_status === 'unpaid')
    .map(({ id, device, total }) => ({ booking_id: id, device, amount: total }));
  const byMonth = {};
  payments.filter((payment) => payment.status === 'paid').forEach((payment) => {
    const key = new Date(payment.created_at * 1000).toISOString().slice(0, 7);
    byMonth[key] = (byMonth[key] || 0) + payment.amount - payment.platform_fee - payment.commission;
  });
  res.json({ gross, commission, net: gross - commission, byMonth, payments, awaitingPayment });
});
r.get('/payments', auth, role('client'), async (req, res) => {
  const [payments, bookings] = await Promise.all([by('payments', 'payer_id', req.user.id), list('bookings')]);
  res.json(payments.filter((p) => p.kind === 'booking').sort((a, b) => b.id - a.id).map((p) => ({ ...p, device: byId(bookings, p.booking_id)?.device })));
});
r.get('/announcements', auth, async (req, res) => res.json((await list('announcements')).filter((x) => x.audience === 'all' || x.audience === req.user.role).sort((a, b) => b.id - a.id).slice(0, 20)));

r.get('/dashboard', auth, async (req, res) => {
  const u = req.user, id = ownerOf(u);
  if (u.role === 'client') {
    const [bookings, messages] = await Promise.all([by('bookings', 'client_id', u.id), by('messages', 'receiver_id', u.id)]);
    return res.json({ cards: [
      { label: 'Active repairs', value: bookings.filter((b) => ['requested', 'accepted', 'in_progress'].includes(b.status)).length },
      { label: 'Completed', value: bookings.filter((b) => b.status === 'completed').length },
      { label: 'Active warranties', value: bookings.filter((b) => b.warranty_until > now()).length },
      { label: 'Unread messages', value: messages.filter((m) => !m.read).length },
    ] });
  }
  if (u.role === 'admin') {
    const permissions = Array.isArray(u.permissions) ? u.permissions : [];
    const can = (permission) => permissions.includes('*') || permissions.includes(permission);
    const [users, bookings, docs, reports, payments, logs] = await Promise.all([
      can('users') ? list('users') : [],
      list('bookings'),
      can('documents') ? list('documents') : [],
      can('reports') ? list('reports') : [],
      can('finance') ? list('payments') : [],
      can('reports') ? list('audit_logs') : [],
    ]);
    const months = new Map();
    payments.filter((p) => p.status === 'paid').forEach((p) => {
      const month = new Date(p.created_at * 1000).toISOString().slice(0, 7);
      months.set(month, (months.get(month) || 0) + (p.kind === 'subscription' ? p.amount : p.commission + p.platform_fee));
    });
    const revenue = [...months].sort(([a], [b]) => b.localeCompare(a)).slice(0, 12).reverse().map(([label, value]) => ({ label, value: Math.round(value) }));
    const cards = [];
    if (can('users')) {
      cards.push(
        { label: 'Clients', value: users.filter((x) => x.role === 'client' && x.status !== 'deleted').length },
        { label: 'Shops', value: users.filter((x) => x.role === 'shop').length },
        { label: 'Technicians', value: users.filter((x) => x.role === 'technician').length },
      );
    }
    cards.push({ label: 'Bookings', value: bookings.length });
    if (can('documents')) cards.push({ label: 'Pending documents', value: docs.filter((x) => x.status === 'pending').length });
    if (can('reports')) cards.push(
      { label: 'Open reports', value: reports.filter((x) => ['open', 'appeal'].includes(x.status)).length },
      { label: 'Security alerts (7d)', value: logs.filter((x) => x.action.startsWith('security.') && x.created_at > now() - 7 * 86400).length },
    );
    if (can('finance')) cards.push({ label: 'Platform revenue (₱)', value: Math.round(revenue.reduce((sum, item) => sum + item.value, 0)) });
    return res.json({ cards, ...(can('finance') ? { chart: revenue, chartTitle: 'Platform revenue by month' } : {}) });
  }
  const [bookings, reviews, payments] = await Promise.all([
    by('bookings', u.shop_id ? 'technician_id' : 'provider_id', u.shop_id ? u.id : id),
    by('reviews', 'provider_id', id),
    by('payments', 'provider_id', id),
  ]);
  const paidBookings = payments.filter((payment) => payment.kind === 'booking' && payment.status === 'paid');
  const netEarnings = paidBookings.reduce((sum, payment) => sum + payment.amount - payment.platform_fee - payment.commission, 0);
  const sub = u.shop_id ? null : await activeSub(id);
  return res.json({ cards: [
    { label: 'New requests', value: bookings.filter((b) => b.status === 'requested').length },
    { label: 'In progress', value: bookings.filter((b) => ['accepted', 'in_progress'].includes(b.status)).length },
    { label: 'Completed', value: bookings.filter((b) => b.status === 'completed').length },
    ...(u.role === 'shop' ? [{ label: 'Net earnings', value: +netEarnings.toFixed(2) }] : []),
    { label: 'Rating', value: reviews.length ? +(reviews.reduce((sum, x) => sum + x.rating, 0) / reviews.length).toFixed(1) : '—' },
    ...(u.shop_id ? [] : [{ label: 'Subscription', value: sub ? 'Active' : 'Inactive' }, { label: 'Verification', value: await approved(u.id) ? 'Approved' : 'Pending' }]),
  ] });
});

export default r;
