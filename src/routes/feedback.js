import { Router } from 'express';
import { query } from '../db.js';
import { isEmail } from '../utils/validate.js';

const router = Router();

/**
 * POST /api/v1/feedback
 * body: { username, email, rating, message? }
 */
router.post('/feedback', async (req, res) => {
  const { username, email, rating, message } = req.body || {};
  if (!username || !email || typeof rating !== 'number') {
    return res.status(400).json({ ok: false, code: 'BAD_REQUEST' });
  }
  if (rating < 1 || rating > 5) {
    return res.status(400).json({ ok: false, code: 'RATING_RANGE', message: 'rating must be 1..5' });
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
    await query(
      `INSERT INTO feedback (user_id, rating, message)
       VALUES ($1, $2, NULLIF($3, ''));`,
      [u.rows[0].id, rating, message ?? '']
    );
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, code: 'DB_ERROR' });
  }
});

export default router;