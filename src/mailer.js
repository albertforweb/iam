import nodemailer from 'nodemailer';

const host = (process.env.IAM_SMTP_HOST ?? '').trim();
const port = Number.parseInt(process.env.IAM_SMTP_PORT ?? '587', 10);
const secure = process.env.IAM_SMTP_SECURE === 'true';
const from = (process.env.IAM_MAIL_FROM ?? '').trim();
const username = (process.env.IAM_SMTP_USERNAME ?? '').trim();
const password = process.env.IAM_SMTP_PASSWORD ?? '';

const transporter = host && from
  ? nodemailer.createTransport({
      host,
      port,
      secure,
      ...(username || password ? { auth: { user: username, pass: password } } : {}),
    })
    : null;

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function isMailConfigured() {
  return !!transporter;
}

export async function sendPasswordResetEmail({ to, username, resetUrl, expiresAt }) {
  if (!transporter) throw new Error('SMTP delivery is not configured');
  const expiry = new Date(expiresAt).toLocaleString();
  const safeUsername = escapeHtml(username);
  const safeResetUrl = escapeHtml(resetUrl);
  return transporter.sendMail({
    from,
    to,
    subject: 'Reset your IAM password',
    text: `Hello ${username},\n\nUse this link to reset your IAM password:\n${resetUrl}\n\nThis link expires at ${expiry} and can only be used once. If you did not request this, you can ignore this email.`,
    html: `<p>Hello ${safeUsername},</p><p>Use the link below to reset your IAM password:</p><p><a href="${safeResetUrl}">Reset your IAM password</a></p><p>This link expires at ${escapeHtml(expiry)} and can only be used once. If you did not request this, you can ignore this email.</p>`,
  });
}
