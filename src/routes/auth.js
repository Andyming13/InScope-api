// src/routes/auth.js
const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const { query } = require('../db');
const { signAccessToken, verifyToken } = require('../utils/jwt');
const { sendMail } = require('../utils/email');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET not set');

// ===== 工具 =====
function generate6DigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function setRefreshCookie(res, raw) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('rt', raw, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd, // 线上必须 https
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30天
  });
}

// 同IP限流
const ipLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

// ===== 健康探针 =====
router.get('/_ping', (_req, res) => res.json({ ok: true }));

// ===== 业务限流：同邮箱10分钟最多5次 =====
async function underEmailQuota(email) {
  const { rows } = await query(
    `select count(*)::int as cnt
       from verification_codes
      where lower(email)=lower($1)
        and created_at > now() - interval '10 minutes'`,
    [email]
  );
  return rows[0].cnt < 5;
}

// ===== 1) 发送验证码 /request-code =====
router.post('/request-code', ipLimiter, async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email().max(200),
      purpose: z.enum(['verify_email', 'reset_password']).default('verify_email'),
    });
    const { email, purpose } = schema.parse(req.body);

    if (!(await underEmailQuota(email))) {
      return res.status(429).json({ ok: false, code: 'TOO_MANY_REQUESTS', message: '请求过于频繁，请稍后再试。' });
    }

    const code = generate6DigitCode();
    const codeHash = await argon2.hash(code, { type: argon2.argon2id });
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10分钟

    await query(
      `insert into verification_codes (email, code_hash, purpose, expires_at, attempts_remaining)
       values ($1,$2,$3,$4,5)`,
      [email, codeHash, purpose, expiresAt]
    );

    // 发邮件（log 模式会在日志打印，resend 模式走 utils/email）
    const subject = purpose === 'verify_email' ? 'InScope 验证码 / Verification Code' : 'InScope 重置密码验证码';
    const text = `您的验证码是 ${code}（10分钟内有效）。If you did not request this, please ignore.`;
    const html = `<p>您的验证码是 <b style="font-size:18px">${code}</b>（10分钟内有效）。</p><p>If you did not request this, please ignore.</p>`;
    await sendMail({ to: email, subject, text, html });

    return res.json({ ok: true });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok: false, code: 'BAD_INPUT', errors: err.errors });
    }
    console.error('REQUEST_CODE_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

// ===== 2) 验证验证码 /verify-code =====
router.post('/verify-code', ipLimiter, async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email().max(200),
      code: z.string().regex(/^\d{6}$/),
      purpose: z.enum(['verify_email', 'reset_password']).default('verify_email'),
    });
    const { email, code, purpose } = schema.parse(req.body);

    const { rows } = await query(
      `select id, code_hash, expires_at, attempts_remaining, created_at
         from verification_codes
        where lower(email)=lower($1)
          and purpose=$2
          and expires_at > now()
          and attempts_remaining > 0
        order by created_at desc
        limit 1`,
      [email, purpose]
    );

    if (!rows.length) {
      return res.status(400).json({ ok: false, code: 'CODE_NOT_FOUND_OR_EXPIRED', message: '验证码不存在或已过期。' });
    }

    const row = rows[0];
    const ok = await argon2.verify(row.code_hash, code);
    if (!ok) {
      await query(`update verification_codes set attempts_remaining = attempts_remaining - 1 where id=$1`, [row.id]);
      return res.status(400).json({ ok: false, code: 'CODE_INCORRECT', message: '验证码不正确。' });
    }

    // 作废此验证码
    await query(`update verification_codes set attempts_remaining = 0 where id=$1`, [row.id]);

    // 签发一次性 registration_token（15分钟）
    const registrationToken = jwt.sign(
      { type: 'registration', email },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.json({ ok: true, registration_token: registrationToken, expires_in_sec: 15 * 60 });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok: false, code: 'BAD_INPUT', errors: err.errors });
    }
    console.error('VERIFY_CODE_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

// ===== 3) 注册 /register  （需要 Bearer registration_token）=====
router.post('/register', ipLimiter, async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ ok: false, code: 'NO_REG_TOKEN', message: '缺少 registration_token。' });

    let claims;
    try {
      claims = jwt.verify(m[1], JWT_SECRET);
    } catch {
      return res.status(401).json({ ok: false, code: 'BAD_REG_TOKEN', message: 'registration_token 无效或已过期。' });
    }
    if (!(claims?.type === 'registration' && claims?.email)) {
      return res.status(401).json({ ok: false, code: 'BAD_REG_TOKEN', message: 'registration_token 不合法。' });
    }
    const email = String(claims.email).toLowerCase();

    const schema = z.object({
      username: z.string().min(3).max(20).regex(/^[a-zA-Z0-9_]+$/, '用户名仅字母/数字/下划线'),
      password: z.string().min(8).max(128),
    });
    const { username, password } = schema.parse(req.body);

    // 重复检查
    const dupe = await query(
      `select
         (exists(select 1 from users where lower(email)=lower($1))) as email_taken,
         (exists(select 1 from users where lower(username)=lower($2))) as username_taken`,
      [email, username]
    );
    if (dupe.rows[0].email_taken) return res.status(409).json({ ok: false, code: 'EMAIL_TAKEN', message: '该邮箱已注册' });
    if (dupe.rows[0].username_taken) return res.status(409).json({ ok: false, code: 'USERNAME_TAKEN', message: '该用户名已被占用' });

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
    const created = await query(
      `insert into users (email, email_verified_at, password_hash, username)
       values ($1, now(), $2, $3)
       returning id, email, username, created_at`,
      [email, passwordHash, username]
    );
    const user = created.rows[0];

    // 生成 Access Token
    const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username });

    // 生成 Refresh Token（入库哈希 & 写 HttpOnly Cookie）
    const rawRt = crypto.randomBytes(32).toString('hex');
    const rtHash = sha256(rawRt);
    const ua = req.headers['user-agent'] || '';
    const ip = (req.ip || '').toString();
    const ipHash = sha256(ip);

    const expiresAt = new Date(Date.now() + 30 * 24 * 3600 * 1000); // 30天
    await query(
      `insert into refresh_tokens (user_id, token_hash, user_agent, ip_hash, expires_at)
       values ($1,$2,$3,$4,$5)`,
      [user.id, rtHash, ua, ipHash, expiresAt]
    );
    setRefreshCookie(res, rawRt);

    res.json({
      ok: true,
      user: { id: user.id, email: user.email, username: user.username },
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in_sec: 15 * 60,
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok: false, code: 'BAD_INPUT', errors: err.errors });
    }
    console.error('REGISTER_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

// ===== 4) 登录 /login =====
router.post('/login', ipLimiter, async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email().max(200),
      password: z.string().min(1),
    });
    const { email, password } = schema.parse(req.body);
    const emailLower = email.toLowerCase();

    const { rows } = await query(
      `select id, email, username, password_hash
         from users
        where lower(email) = $1
        limit 1`,
      [emailLower]
    );
    if (!rows.length) {
      return res.status(401).json({ ok: false, code: 'INVALID_CREDENTIALS', message: '邮箱或密码不正确。' });
    }

    const user = rows[0];
    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
      return res.status(401).json({ ok: false, code: 'INVALID_CREDENTIALS', message: '邮箱或密码不正确。' });
    }

    await query(`update users set last_login_at = now() where id = $1`, [user.id]).catch(() => {});

    const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username });

    const rawRt = crypto.randomBytes(32).toString('hex');
    const rtHash = sha256(rawRt);
    const ua = req.headers['user-agent'] || '';
    const ip = (req.ip || '').toString();
    const ipHash = sha256(ip);
    const expiresAt = new Date(Date.now() + 30 * 24 * 3600 * 1000);

    await query(
      `insert into refresh_tokens (user_id, token_hash, user_agent, ip_hash, expires_at)
       values ($1,$2,$3,$4,$5)`,
      [user.id, rtHash, ua, ipHash, expiresAt]
    );
    setRefreshCookie(res, rawRt);

    res.json({
      ok: true,
      user: { id: user.id, email: user.email, username: user.username },
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in_sec: 15 * 60,
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok: false, code: 'BAD_INPUT', errors: err.errors });
    }
    console.error('LOGIN_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

// ===== 5) 刷新 /refresh =====
router.post('/refresh', ipLimiter, async (req, res) => {
  try {
    const rawRt = (req.cookies && req.cookies.rt) || '';
    if (!rawRt) return res.status(401).json({ ok: false, code: 'NO_REFRESH', message: '缺少刷新令牌。' });

    const rtHash = sha256(rawRt);
    const { rows } = await query(
      `select user_id, expires_at
         from refresh_tokens
        where token_hash = $1
          and expires_at > now()
        limit 1`,
      [rtHash]
    );
    if (!rows.length) {
      return res.status(401).json({ ok: false, code: 'BAD_REFRESH', message: '刷新令牌无效或已过期。' });
    }

    const userId = rows[0].user_id;
    const u = await query(`select id, email, username from users where id = $1 limit 1`, [userId]);
    if (!u.rows.length) {
      return res.status(401).json({ ok: false, code: 'USER_GONE', message: '用户不存在。' });
    }
    const user = u.rows[0];

    // 旋转 refresh token：生成新 token，入库并删除旧 token
    const newRt = crypto.randomBytes(32).toString('hex');
    const newRtHash = sha256(newRt);
    const ua = req.headers['user-agent'] || '';
    const ip = (req.ip || '').toString();
    const ipHash = sha256(ip);
    const expiresAt = new Date(Date.now() + 30 * 24 * 3600 * 1000);

    await query('BEGIN');
    await query(
      `insert into refresh_tokens (user_id, token_hash, user_agent, ip_hash, expires_at)
       values ($1,$2,$3,$4,$5)`,
      [user.id, newRtHash, ua, ipHash, expiresAt]
    );
    await query(`delete from refresh_tokens where token_hash = $1`, [rtHash]);
    await query('COMMIT');

    setRefreshCookie(res, newRt);
    const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username });

    res.json({ ok: true, user, access_token: accessToken, token_type: 'Bearer', expires_in_sec: 15 * 60 });
  } catch (err) {
    try { await query('ROLLBACK'); } catch {}
    console.error('REFRESH_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

// ===== 6) 退出 /logout =====
router.post('/logout', ipLimiter, async (req, res) => {
  try {
    const rawRt = (req.cookies && req.cookies.rt) || '';
    if (rawRt) {
      const rtHash = sha256(rawRt);
      await query(`delete from refresh_tokens where token_hash = $1`, [rtHash]).catch(() => {});
    }
    res.clearCookie('rt', { httpOnly: true, sameSite: 'lax', path: '/' });
    res.json({ ok: true });
  } catch (err) {
    console.error('LOGOUT_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

// ===== 7) 我 /me =====
router.get('/me', async (req, res) => {
  try {
    const h = req.headers.authorization || '';
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ ok: false, code: 'NO_ACCESS_TOKEN' });

    let claims;
    try {
      claims = verifyToken(m[1]);
    } catch {
      return res.status(401).json({ ok: false, code: 'BAD_ACCESS_TOKEN' });
    }
    if (!claims?.sub) {
      return res.status(401).json({ ok: false, code: 'BAD_ACCESS_TOKEN' });
    }

    const { rows } = await query(`select id, email, username from users where id=$1 limit 1`, [claims.sub]);
    if (!rows.length) return res.status(404).json({ ok: false, code: 'USER_NOT_FOUND' });
    res.json({ ok: true, user: rows[0] });
  } catch (err) {
    console.error('ME_ERROR', err);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

module.exports = router;