// src/utils/jwt.js
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET;
if (!SECRET) throw new Error('JWT_SECRET not set');

function signAccessToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: '7d' });
}
function verifyToken(token) {
  return jwt.verify(token, SECRET);
}
module.exports = { signAccessToken, verifyToken };