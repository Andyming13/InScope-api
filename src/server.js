// src/server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { ping } = require('./db');

const app = express();
app.set('trust proxy', 1);

// CORS
const raw = process.env.CORS_ORIGIN || 'http://localhost:8000';
const ALLOWED_ORIGINS = raw.split(',').map(s => s.trim()).filter(Boolean);
const corsOpts = {
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true,
};

app.use(cors(corsOpts));
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

// 健康检查（含 DB）
app.get('/healthz', async (_req, res) => {
  try {
    const now = await ping();
    res.json({ ok:true, now });
  } catch (e) {
    res.status(500).json({ ok:false, error:'DB_UNREACHABLE', detail:String(e.message||e) });
  }
});

// 路由
app.get('/api/v1/hello', (_req, res) => res.json({ message: 'InScope API ready' }));
app.use('/api/v1/auth', require('./routes/auth'));
app.use('/api/v1', require('./routes/courses'));

// 启动
const PORT = Number(process.env.PORT || 8787);
app.listen(PORT, () => {
  console.log(`InScope API listening on :${PORT}`);
  console.log('CORS origins allowed:', ALLOWED_ORIGINS);
});