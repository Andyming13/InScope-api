// src/routes/auth.js
const express = require('express');
const router = express.Router();
const { query } = require('../db');
const argon2 = require('argon2');
const { z } = require('zod');
const { signAccessToken } = require('../utils/jwt');

const emailSchema = z.string().email();
const passwordSchema = z.string().min(6, '密码至少 6 位');
const usernameSchema = z.string().min(3).max(20).regex(/^[a-zA-Z0-9_]+$/, '用户名仅字母/数字/下划线');

// 注册：email + username + password
router.post('/register', async (req, res) => {
  try {
    const { email, username, password } = req.body || {};
    const e = emailSchema.parse(email).toLowerCase();
    const u = usernameSchema.parse(username);
    const p = passwordSchema.parse(password);

    // 是否已存在
    const { rows: exist } = await query(
      `SELECT
         (EXISTS(SELECT 1 FROM users WHERE lower(email)=lower($1))) AS email_taken,
         (EXISTS(SELECT 1 FROM users WHERE lower(username)=lower($2))) AS username_taken`,
      [e, u]
    );
    if (exist[0].email_taken) return res.status(409).json({ ok:false, message:'邮箱已注册' });
    if (exist[0].username_taken) return res.status(409).json({ ok:false, message:'用户名已被占用' });

    const hash = await argon2.hash(p, { type: argon2.argon2id });

    const { rows } = await query(
      `INSERT INTO users (email, username, password_hash, email_verified, created_at)
       VALUES ($1,$2,$3,false,now())
       RETURNING id, email, username`,
      [e, u, hash]
    );
    const user = rows[0];
    const token = signAccessToken({ sub: user.id, email: user.email, username: user.username });
    res.json({ ok:true, user, access_token: token, token_type:'Bearer', expires_in_sec: 7*24*3600 });
  } catch (err) {
    if (err.errors) return res.status(400).json({ ok:false, message: err.errors[0].message });
    res.status(500).json({ ok:false, message:'注册失败', detail:String(err.message||err) });
  }
});

// 登录：email + password
router.post('/login', async (req, res) => {
  try {
    const { email, password } = z.object({
      email: emailSchema,
      password: z.string().min(1),
    }).parse(req.body);
    const e = email.toLowerCase();

    const { rows } = await query(
      `SELECT id, email, username, password_hash FROM users WHERE lower(email)=lower($1) LIMIT 1`,
      [e]
    );
    if (!rows.length) return res.status(401).json({ ok:false, message:'邮箱或密码不正确' });

    const user = rows[0];
    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) return res.status(401).json({ ok:false, message:'邮箱或密码不正确' });

    await query(`UPDATE users SET last_login_at = now() WHERE id=$1`, [user.id]).catch(()=>{});
    const token = signAccessToken({ sub: user.id, email: user.email, username: user.username });
    res.json({ ok:true, user: { id:user.id, email:user.email, username:user.username }, access_token: token, token_type:'Bearer', expires_in_sec: 7*24*3600 });
  } catch (err) {
    if (err.errors) return res.status(400).json({ ok:false, message: err.errors[0].message });
    res.status(500).json({ ok:false, message:'登录失败', detail:String(err.message||err) });
  }
});

module.exports = router;