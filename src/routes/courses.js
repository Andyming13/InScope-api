// src/routes/courses.js
const express = require('express');
const rateLimit = require('express-rate-limit');
const { query } = require('../db');
const { verifyToken } = require('../utils/jwt');

const router = express.Router();

// 基础限流
const ipLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// 统一封装：从 Authorization 里解析用户
async function getUserFromAuth(req, res) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    res.status(401).json({ ok: false, code: 'NO_ACCESS_TOKEN', message: '请先登录后再报名。' });
    return null;
  }
  let claims;
  try {
    claims = verifyToken(m[1]);
  } catch (e) {
    res.status(401).json({ ok: false, code: 'BAD_ACCESS_TOKEN', message: '登录已失效，请重新登录。' });
    return null;
  }
  if (!claims?.sub) {
    res.status(401).json({ ok: false, code: 'BAD_ACCESS_TOKEN', message: '登录已失效，请重新登录。' });
    return null;
  }
  return { userId: claims.sub, email: claims.email, username: claims.username };
}

// GET /api/v1/courses  列表
router.get('/', ipLimiter, async (_req, res) => {
  try {
    const { rows } = await query(
      `select id::text, title, description, start_time, end_time
         from courses
        order by start_time asc`
    );
    res.json({ ok: true, data: rows });
  } catch (err) {
    console.error('COURSES_LIST_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

// POST /api/v1/courses/:id/enroll  报名
router.post('/:id/enroll', ipLimiter, async (req, res) => {
  try {
    const auth = await getUserFromAuth(req, res);
    if (!auth) return;
    const userId = auth.userId;
    const courseId = Number(req.params.id);

    if (!Number.isFinite(courseId) || courseId <= 0) {
      return res.status(400).json({ ok: false, code: 'BAD_COURSE_ID', message: '课程 ID 不合法。' });
    }

    // 查课程是否存在
    const course = await query(`select id from courses where id = $1`, [courseId]);
    if (!course.rows.length) {
      return res.status(404).json({ ok: false, code: 'COURSE_NOT_FOUND', message: '课程不存在。' });
    }

    // 已报过名？
    const existed = await query(
      `select 1 from enrollments where user_id = $1 and course_id = $2 limit 1`,
      [userId, courseId]
    );
    if (existed.rows.length) {
      return res.status(409).json({ ok: false, code: 'ALREADY_ENROLLED', message: '你已报名该课程。' });
    }

    // 容量限制：30 人
    const cap = 30;
    const cnt = await query(
      `select count(*)::int as c from enrollments where course_id = $1`,
      [courseId]
    );
    if (cnt.rows[0].c >= cap) {
      return res.status(409).json({ ok: false, code: 'COURSE_FULL', message: '该课程报名已满。' });
    }

    // 入库
    await query(
      `insert into enrollments (user_id, course_id) values ($1, $2)`,
      [userId, courseId]
    );

    console.log('[ENROLL] ok', { userId, courseId });
    return res.json({ ok: true });
  } catch (err) {
    // 如果是唯一约束触发（user_id, course_id）
    if (String(err?.code) === '23505') {
      return res.status(409).json({ ok: false, code: 'ALREADY_ENROLLED', message: '你已报名该课程。' });
    }
    console.error('ENROLL_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: '报名失败，请稍后再试。' });
  }
});

// GET /api/v1/courses/mine  我报名的课程
router.get('/mine', ipLimiter, async (req, res) => {
  try {
    const auth = await getUserFromAuth(req, res);
    if (!auth) return;
    const userId = auth.userId;

    const { rows } = await query(
      `select c.id::text, c.title, c.start_time, c.end_time, e.created_at as enrolled_at
         from enrollments e
         join courses c on c.id = e.course_id
        where e.user_id = $1
        order by c.start_time asc`,
      [userId]
    );
    res.json({ ok: true, data: rows });
  } catch (err) {
    console.error('MINE_COURSES_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

module.exports = router;