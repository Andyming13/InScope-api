// src/utils/email.js
const fetch = require('node-fetch');

async function sendVerifyEmail({ to, code }) {
  const mode = process.env.EMAIL_MODE || 'log';

  if (mode === 'log') {
    console.log(`[DEV EMAIL] To: ${to} Code: ${code}`);
    return;
  }

  if (mode === 'resend') {
    const apiKey = process.env.RESEND_API_KEY;
    const from = process.env.EMAIL_FROM || 'InScope <noreply@inscopei1.com.au>';

    if (!apiKey) throw new Error('RESEND_API_KEY not set');

    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to,
        subject: 'Your InScope verification code',
        html: `<p>Hi,</p>
               <p>Your verification code is:</p>
               <h2 style="color:#1E3AFF">${code}</h2>
               <p>This code will expire in 10 minutes.</p>`,
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error('Resend API error:', errText);
      throw new Error(`Failed to send email: ${resp.status}`);
    }

    console.log(`[RESEND] Sent verification code to ${to}`);
    return;
  }

  throw new Error(`EMAIL_MODE ${mode} not supported`);
}

module.exports = { sendVerifyEmail };