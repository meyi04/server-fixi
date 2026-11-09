import 'express-async-errors';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import authRoutes from './routes/auth.js';
import core from './routes/core.js';
import admin from './routes/admin.js';
import { MAX_UPLOAD_BYTES, streamUpload } from './db.js';

export function createApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
  app.use(cors());
  app.use(express.json({ limit: '100kb' }));
  app.use('/api', rateLimit({ windowMs: 60e3, limit: 300, standardHeaders: true, legacyHeaders: false }));
  app.use('/api/auth', rateLimit({ windowMs: 15 * 60e3, limit: 40, standardHeaders: true, legacyHeaders: false }));
  app.get(['/uploads/public/:filename', '/api/uploads/public/:filename'], (req, res, next) => {
    if (path.basename(req.params.filename) !== req.params.filename) return res.status(404).end();
    streamUpload(`public/${req.params.filename}`, res).catch(next);
  });
  app.use('/api/auth', authRoutes);
  app.use('/api/admin', admin);
  app.use('/api', core);
  app.use("/health", (req, res) => {
    res.send("ok");
  })
  app.use((req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((err, req, res, next) => {
    if (err.name === 'ZodError') return res.status(400).json({ error: err.issues.map((i) => i.message).join('; ') });
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: `File too large (max ${Math.floor(MAX_UPLOAD_BYTES / 1024)} KB)` });
    if (err.status === 400) return res.status(400).json({ error: err.message });
    if (/File type/.test(err.message)) return res.status(400).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  });
  return app;
}
