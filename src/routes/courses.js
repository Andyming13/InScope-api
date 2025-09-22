// src/routes/courses.js
const express = require('express');
const router = express.Router();
const { query } = require('../db');
const { z } = require('zod');
const { verifyToken } = require('../utils/jwt');

// 简易鉴权（Authorization: Bearer <token>）
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok:false, message:'未登录' });
  try {
    const claims = verifyToken(m[1]);
    const uid = claims.sub || claims.uid;
    if (!uid) return res.status(401).json({ ok:false, message:'令牌缺少用户ID' });
    req.user = { id: uid, email: claims.email, username: claims.username };
    next();
  } catch {
    return res.status(401).json({ ok:false, message:'登录已失效' });
  }
}

// 公开：列课程
router.get('/courses', async (_req, res) => {
  try {
    const { rows } = await query(
      `SELECT id, title, description, start_time, end_time
         FROM courses
        ORDER BY start_time ASC`
    );
    res.json({ ok:true, data: rows });
  } catch (e) {
    res.status(500).json({ ok:false, message:'获取课程失败', detail:String(e.message||e) });
  }
});

// 登录：报名
router.post('/enroll', auth, async (req, res) => {
  try {
    const { course_id } = z.object({ course_id: z.number().int().positive() }).parse(req.body);
    const { rows: c } = await query('SELECT id FROM courses WHERE id=$1', [course_id]);
    if (!c.length) return res.status(404).json({ ok:false, message:'课程不存在' });

    await query(
      `INSERT INTO enrollments (user_id, course_id) VALUES ($1,$2)
       ON CONFLICT (user_id, course_id) DO NOTHING`,
      [req.user.id, course_id]
    );
    res.json({ ok:true, message:'报名成功' });
  } catch (e) {
    if (e.errors) return res.status(400).json({ ok:false, message: e.errors[0].message });
    res.status(500).json({ ok:false, message:'报名失败', detail:String(e.message||e) });
  }
});

// 登录：查看我的报名
router.get('/me/enrollments', auth, async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT e.course_id, c.title, c.start_time, c.end_time, e.created_at AS enrolled_at
         FROM enrollments e
         JOIN courses c ON c.id = e.course_id
        WHERE e.user_id = $1
        ORDER BY c.start_time ASC`,
      [req.user.id]
    );
    res.json({ ok:true, data: rows });
  } catch (e) {
    res.status(500).json({ ok:false, message:'获取报名失败', detail:String(e.message||e) });
  }
});

module.exports = router;