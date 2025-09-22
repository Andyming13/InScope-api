// src/utils/email.js
// 先占位：EMAIL_MODE=log 时只打印；resend 时使用 Resend SDK（后续需要我再给你接入）
async function sendMail({ to, subject, html, text }) {
    const mode = (process.env.EMAIL_MODE || 'log').toLowerCase();
    if (mode === 'log') {
      console.log('[MAIL LOG]', { to, subject, text, html });
      return { ok: true, mode };
    }
    // TODO: 集成 Resend（需要 RESEND_API_KEY / EMAIL_FROM）
    console.warn('EMAIL_MODE set to resend, but resend integration not implemented yet.');
    return { ok: false, mode };
  }
  module.exports = { sendMail };