import { Router } from 'express';
import { query } from '../db.js';
import { isEmail } from '../utils/validate.js';

const router = Router();

/**
 * POST /api/v1/intake
 * body: { username, email }
 */
router.post('/intake', async (req, res) => {
  const { username, email } = req.body || {};
  if (!username || !email) {
    return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'username and email required' });
  }
  if (!isEmail(email)) {
    return res.status(400).json({ ok: false, code: 'INVALID_EMAIL' });
  }
  try {
    const sql = `
      INSERT INTO users (username, email)
      VALUES ($1, $2)
      ON CONFLICT (email) DO UPDATE SET username = EXCLUDED.username
      RETURNING id, username, email, created_at;
    `;
    const { rows } = await query(sql, [username, email]);
    return res.json({ ok: true, user: rows[0] });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, code: 'DB_ERROR' });
  }
});

export default router;