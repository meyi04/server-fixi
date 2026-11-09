import admin from 'firebase-admin';
import crypto from 'crypto';

if (!admin.apps.length) {
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;
  let credential = admin.credential.applicationDefault();
  if (serviceAccountJson) {
    let serviceAccount;
    try {
      serviceAccount = JSON.parse(serviceAccountJson);
    } catch {
      throw new Error('FIREBASE_SERVICE_ACCOUNT must contain valid service-account JSON');
    }
    if (process.env.FIREBASE_PROJECT_ID && serviceAccount.project_id !== process.env.FIREBASE_PROJECT_ID) {
      throw new Error('FIREBASE_SERVICE_ACCOUNT project_id must match FIREBASE_PROJECT_ID');
    }
    credential = admin.credential.cert(serviceAccount);
  }
  const options = { credential };
  if (process.env.FIREBASE_PROJECT_ID) options.projectId = process.env.FIREBASE_PROJECT_ID;
  admin.initializeApp(options);
}

export const db = admin.firestore();
export const auth = admin.auth();
const projectId = process.env.FIREBASE_PROJECT_ID || process.env.GCLOUD_PROJECT;
if (!projectId) throw new Error('FIREBASE_PROJECT_ID is required');
const fileExtensions = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'application/pdf': '.pdf' };
export const MAX_UPLOAD_BYTES = 700 * 1024;
const emailKey = (email) => crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
const ref = (collection, id) => db.collection(collection).doc(String(id));

export async function saveUpload(folder, file) {
  if (!file?.buffer) throw Object.assign(new Error('File is required'), { status: 400 });
  if (file.buffer.length > MAX_UPLOAD_BYTES) throw Object.assign(new Error('File too large (max 700 KB)'), { status: 400 });
  if (!fileExtensions[file.mimetype]) throw Object.assign(new Error('File type not allowed'), { status: 400 });
  const filename = `${crypto.randomUUID()}${fileExtensions[file.mimetype]}`;
  await db.collection('_uploads').doc(filename).create({
    folder,
    contentType: file.mimetype,
    data: file.buffer.toString('base64'),
    created_at: Math.floor(Date.now() / 1000),
  });
  return filename;
}

export async function streamUpload(objectPath, res, download = false) {
  const [folder, filename, ...extra] = objectPath.split('/');
  if (!folder || !filename || extra.length) return res.status(404).end();
  const snapshot = await db.collection('_uploads').doc(filename).get();
  if (!snapshot.exists || snapshot.data().folder !== folder) return res.status(404).end();
  const file = snapshot.data();
  res.set('Content-Type', file.contentType || 'application/octet-stream');
  res.set('X-Content-Type-Options', 'nosniff');
  if (download) res.set('Content-Disposition', 'attachment');
  res.send(Buffer.from(file.data, 'base64'));
}

export async function deleteUpload(objectPath) {
  const [folder, filename, ...extra] = objectPath.split('/');
  if (!folder || !filename || extra.length) return;
  const uploadRef = db.collection('_uploads').doc(filename);
  const snapshot = await uploadRef.get();
  if (snapshot.exists && snapshot.data().folder === folder) await uploadRef.delete();
}

export const get = async (collection, id) => {
  const snap = await ref(collection, id).get();
  return snap.exists ? snap.data() : null;
};

export async function list(collection, { where = [], orderBy, direction = 'asc', limit } = {}) {
  let query = db.collection(collection);
  for (const [field, operator, value] of where) query = query.where(field, operator, value);
  if (orderBy) query = query.orderBy(orderBy, direction);
  if (limit) query = query.limit(limit);
  const snapshot = await query.get();
  return snapshot.docs.map((document) => document.data());
}

export async function find(collection, field, value) {
  const rows = await list(collection, { where: [[field, '==', value]], limit: 1 });
  return rows[0] ?? null;
}

export async function create(collection, data) {
  const counter = ref('_counters', collection);
  return db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(counter);
    const id = (snapshot.data()?.value ?? 0) + 1;
    transaction.set(counter, { value: id });
    transaction.create(ref(collection, id), { id, ...data });
    return id;
  });
}

export async function completeBookingWithPayment(bookingId, bookingPatch, paymentData) {
  const bookingRef = ref('bookings', bookingId);
  const paymentRef = ref('_bookingPayments', bookingId);
  const counterRef = ref('_counters', 'payments');
  return db.runTransaction(async (transaction) => {
    const [booking, existingPayment, counter] = await Promise.all([
      transaction.get(bookingRef), transaction.get(paymentRef), transaction.get(counterRef),
    ]);
    if (!booking.exists || !['in_progress', 'completed'].includes(booking.data().status)
      || booking.data().payment_status === 'refunded' || existingPayment.exists) return false;
    if (booking.data().status === 'in_progress'
      && booking.data().payment_status && booking.data().payment_status !== 'unpaid') return false;
    const id = (counter.data()?.value ?? 0) + 1;
    transaction.set(counterRef, { value: id });
    transaction.create(ref('payments', id), { id, ...paymentData });
    transaction.create(paymentRef, { payment_id: id });
    transaction.update(bookingRef, { ...bookingPatch, payment_status: 'paid', updated_at: Math.floor(Date.now() / 1000) });
    return true;
  });
}

export async function createUnique(collection, uniqueField, uniqueValue, data) {
  const uniqueId = crypto.createHash('sha256').update(`${collection}:${uniqueField}:${uniqueValue}`).digest('hex');
  const uniqueRef = ref('_unique', uniqueId);
  const counter = ref('_counters', collection);
  return db.runTransaction(async (transaction) => {
    const [existing, count] = await Promise.all([transaction.get(uniqueRef), transaction.get(counter)]);
    if (existing.exists) return null;
    const id = (count.data()?.value ?? 0) + 1;
    transaction.set(counter, { value: id });
    transaction.create(ref(collection, id), { id, ...data });
    transaction.create(uniqueRef, { id });
    return id;
  });
}

export async function createUser(data, profile = {}) {
  const email = data.email.toLowerCase();
  const emailRef = ref('_userEmails', emailKey(email));
  const counter = ref('_counters', 'users');
  return db.runTransaction(async (transaction) => {
    const existing = await transaction.get(emailRef);
    if (existing.exists) return null;
    const count = await transaction.get(counter);
    const id = (count.data()?.value ?? 0) + 1;
    transaction.set(counter, { value: id });
    transaction.create(ref('users', id), { id, ...data, email });
    transaction.create(ref('profiles', id), { user_id: id, gallery: [], working_hours: {}, ...profile });
    transaction.create(emailRef, { user_id: id });
    return id;
  });
}

export async function createAuthUser(data, profile = {}) {
  const email = data.email.toLowerCase();
  const authUser = await auth.createUser({
    email,
    password: data.password,
    displayName: data.name,
    emailVerified: data.emailVerified ?? false,
    disabled: data.status !== 'active',
  });
  try {
    const id = await createUser({
      role: data.role, email, name: data.name, phone: data.phone ?? null, avatar: null,
      status: data.status ?? 'active', shop_id: data.shop_id ?? null,
      permissions: data.permissions ?? [], created_at: Math.floor(Date.now() / 1000),
      firebase_uid: authUser.uid,
    }, profile);
    if (id === null) {
      await auth.deleteUser(authUser.uid);
      return null;
    }
    return id;
  } catch (error) {
    await auth.deleteUser(authUser.uid);
    throw error;
  }
}

export async function update(collection, id, patch) {
  await ref(collection, id).update(patch);
}

export async function set(collection, id, data) {
  await ref(collection, id).set(data, { merge: true });
}

export async function remove(collection, id) {
  await ref(collection, id).delete();
}

export async function updateMany(collection, where, patch) {
  let query = db.collection(collection);
  for (const [field, operator, value] of where) query = query.where(field, operator, value);
  const snapshot = await query.get();
  for (let offset = 0; offset < snapshot.docs.length; offset += 400) {
    const batch = db.batch();
    snapshot.docs.slice(offset, offset + 400).forEach((document) => batch.set(document.ref, patch, { merge: true }));
    await batch.commit();
  }
  return snapshot.size;
}

export const setting = async (key, fallback) => (await get('settings', key))?.value ?? fallback;

export async function initializeDatabase({
  adminEmail = process.env.ADMIN_EMAIL || 'admin@fixify.local',
  adminPassword = process.env.ADMIN_PASSWORD,
} = {}) {
  const settings = await list('settings', { limit: 1 });
  if (!settings.length) {
    for (const [key, value] of Object.entries({
      platform_fee_pct: '2', default_commission_pct: '10', maintenance: '0',
      terms: 'Fixify terms of service.',
    })) await set('settings', key, { key, value });

    for (const name of ['Smartphone', 'Tablet', 'Laptop', 'Smartwatch', 'Game console'])
      await create('categories', { name, kind: 'device', active: true });
    for (const name of ['Screen replacement', 'Battery replacement', 'Water damage', 'Charging port', 'Software / unlocking', 'Camera repair'])
      await create('categories', { name, kind: 'repair', active: true });
    for (const [name, role, price, commission_pct] of [
      ['Shop Basic', 'shop', 499, 12], ['Shop Pro', 'shop', 999, 8],
      ['Technician Basic', 'technician', 199, 12], ['Technician Pro', 'technician', 399, 8],
    ]) await create('plans', { name, role, price, interval_days: 30, commission_pct, active: true });
  }

  const email = adminEmail.toLowerCase();
  const existing = await find('users', 'email', email);
  if (existing && existing.role !== 'admin') throw new Error('ADMIN_EMAIL is already registered as a non-admin account');

  let firebaseUser;
  try {
    firebaseUser = await auth.getUserByEmail(email);
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error;
    if (!existing && !adminPassword) {
      throw new Error('Set ADMIN_PASSWORD to create the first Firebase admin account');
    }
    firebaseUser = await auth.createUser({
      email, password: adminPassword, displayName: existing?.name || 'Super Admin', emailVerified: true,
    });
    console.log(`[fixify] Firebase admin created: ${email}`);
  }

  if (!firebaseUser.emailVerified || firebaseUser.disabled) {
    firebaseUser = await auth.updateUser(firebaseUser.uid, { emailVerified: true, disabled: false });
  }
  if (!existing) {
    await createUser({
      role: 'admin', email, name: firebaseUser.displayName || 'Super Admin', status: 'active',
      permissions: ['*'], created_at: Math.floor(Date.now() / 1000), firebase_uid: firebaseUser.uid,
    });
  } else if (existing.firebase_uid !== firebaseUser.uid || existing.status !== 'active' || !existing.permissions?.includes('*')) {
    await update('users', existing.id, { firebase_uid: firebaseUser.uid, status: 'active', permissions: ['*'] });
    console.log(`[fixify] Linked existing admin record to Firebase Authentication: ${email}`);
  }
}
