import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';

import intakeRouter from './routes/intake.js';
import coursesRouter from './routes/courses.js';
import feedbackRouter from './routes/feedback.js';
import healthRouter from './routes/health.js';

dotenv.config();

const app = express();

// CORS
const origins = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || origins.includes('*') || origins.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

// Routes
app.use('/api/v1', intakeRouter);
app.use('/api/v1', coursesRouter);
app.use('/api/v1', feedbackRouter);
app.use('/api/v1', healthRouter);

// 404
app.use((req, res) => res.status(404).json({ ok: false, code: 'NOT_FOUND' }));

// Start
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`InScope backend listening on :${port}`));