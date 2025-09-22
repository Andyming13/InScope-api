// src/utils/email.js
// Node 18+ 自带 fetch，这里直接用全局 fetch，无需安装 node-fetch

function toPlainText(htmlOrText) {
    if (!htmlOrText) return '';
    // 简单把 <br> 转为换行，去掉其它标签
    return String(htmlOrText)
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<[^>]+>/g, '')
      .trim();
  }
  
  /**
   * 统一发信函数（auth.js 用的是这个）
   * @param {Object} param0
   * @param {string} param0.to
   * @param {string} param0.subject
   * @param {string} [param0.text]
   * @param {string} [param0.html]
   */
  async function sendMail({ to, subject, text, html }) {
    const mode = (process.env.EMAIL_MODE || 'log').trim().toLowerCase();
  
    if (mode === 'log') {
      const preview = text || toPlainText(html) || '(no body)';
      console.log(`[DEV EMAIL] To: ${to}\nSubject: ${subject}\nBody: ${preview}`);
      return;
    }
  
    if (mode === 'resend') {
      const apiKey = (process.env.RESEND_API_KEY || '').trim();
      const from = (process.env.EMAIL_FROM || 'InScope <noreply@inscopei1.com.au>').trim();
      if (!apiKey) throw new Error('RESEND_API_KEY not set');
      if (!from.includes('@')) throw new Error('EMAIL_FROM is invalid');
  
      const resp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from,
          to,
          subject,
          html: html || (text ? `<pre>${escapeHtml(text)}</pre>` : ''),
          text: text || toPlainText(html || ''),
        }),
      });
  
      if (!resp.ok) {
        const errText = await resp.text().catch(() => '');
        console.error('Resend API error:', resp.status, errText);
        throw new Error(`Failed to send email via Resend: ${resp.status}`);
      }
      console.log(`[RESEND] Sent email to ${to} (${subject})`);
      return;
    }
  
    throw new Error(`EMAIL_MODE ${mode} not supported`);
  }
  
  /**
   * 兼容早期代码：直接发 6 位验证码
   */
  async function sendVerifyEmail({ to, code }) {
    const subject = 'Your InScope verification code';
    const text = `Your verification code is: ${code}\nThis code will expire in 10 minutes.`;
    const html = `<p>Your verification code is:</p>
                  <h2 style="color:#1E3AFF">${code}</h2>
                  <p>This code will expire in 10 minutes.</p>`;
    return sendMail({ to, subject, text, html });
  }
  
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }
  
  module.exports = { sendMail, sendVerifyEmail };