import { Router } from 'express';
import { query } from '../db.js';
import { isEmail } from '../utils/validate.js';

const router = Router();

/**
 * GET /api/v1/courses
 */
router.get('/courses', async (_req, res) => {
  try {
    const { rows } = await query(
      'SELECT id, title, event_date, time_text, location_text, max_member FROM courses ORDER BY event_date ASC;'
    );
    return res.json({ ok: true, data: rows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, code: 'DB_ERROR' });
  }
});

/**
 * POST /api/v1/courses/:id/enroll
 * body: { username, email }
 */
router.post('/courses/:id/enroll', async (req, res) => {
  const courseId = req.params.id;
  const { username, email } = req.body || {};
  if (!username || !email) {
    return res.status(400).json({ ok: false, code: 'BAD_REQUEST' });
  }
  if (!isEmail(email)) {
    return res.status(400).json({ ok: false, code: 'INVALID_EMAIL' });
  }
  try {
    const u = await query(
      `INSERT INTO users (username, email)
       VALUES ($1, $2)
       ON CONFLICT (email) DO UPDATE SET username = EXCLUDED.username
       RETURNING id;`,
      [username, email]
    );
    const userId = u.rows[0].id;

    await query(
      `INSERT INTO enrollments (user_id, course_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id, course_id) DO NOTHING;`,
      [userId, courseId]
    );

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, code: 'DB_ERROR' });
  }
});

export default router;