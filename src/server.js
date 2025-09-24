// src/server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { ping } = require('./db');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// ===== CORS（支持 Authorization + 预检）=====
const raw = process.env.CORS_ORIGIN || 'http://localhost:5173';
const ALLOWED_ORIGINS = raw.split(',').map(s => s.trim()).filter(Boolean);

// 允许的方法和头
const CORS_METHODS = ['GET','POST','PUT','DELETE','OPTIONS'];
const CORS_HEADERS = ['Content-Type','Authorization'];

app.use(cors({
  origin(origin, cb) {
    // 无 Origin（比如健康检查、curl）放行
    if (!origin) return cb(null, true);
    const ok = ALLOWED_ORIGINS.includes(origin);
    cb(ok ? null : new Error(`CORS blocked: ${origin}`), ok);
  },
  credentials: true,
  methods: CORS_METHODS,
  allowedHeaders: CORS_HEADERS,
  maxAge: 600, // 预检缓存 10 分钟
}));

// 显式处理所有 OPTIONS 预检
app.options('*', cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true,
  methods: CORS_METHODS,
  allowedHeaders: CORS_HEADERS,
}));

// 基础限流
const limiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// 健康检查（连 DB）
app.get('/healthz', async (_req, res) => {
  try {
    const now = await ping();
    res.json({ ok: true, now });
  } catch (e) {
    console.error('[DB ERROR]', e.code, e.message);
    res.status(500).json({ ok: false, error: 'DB_UNREACHABLE' });
  }
});

// 简单 API
app.get('/api/v1/hello', (_req, res) => {
  res.json({ message: 'InScope API ready' });
});

// 加一条日志，排查卡住位置（可留着）
app.use((req, _res, next) => {
  if (req.path.startsWith('/api/v1/auth/register')) {
    console.log('[REGISTER] incoming', { method: req.method, origin: req.headers.origin });
  }
  next();
});

// 路由
const authRoutes = require('./routes/auth');
const courseRoutes = require('./routes/courses');
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/courses', courseRoutes);

const PORT = Number(process.env.PORT || 8787);
app.listen(PORT, () => {
  console.log(`InScope API listening on :${PORT}`);
  console.log('CORS origins allowed:', ALLOWED_ORIGINS);
});

app.set('trust proxy', 1);