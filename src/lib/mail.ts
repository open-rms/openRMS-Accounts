import nodemailer, { type Transporter } from "nodemailer";
import { env } from "../env.js";

/**
 * Mail sender. With SMTP_URL set, mail goes through that server: e.g.
 * `smtps://api_token:<token>@smtp.mx.cloudflare.net:465` (implicit TLS) or
 * `smtp://user:pass@host:587` (STARTTLS). The sender is MAIL_FROM.
 * Without SMTP_URL, messages are logged (stdout / journal) so development needs no mail server.
 */
let transport: Transporter | null = null;

function smtp(): Transporter {
  transport ??= nodemailer.createTransport(env.SMTP_URL!, { from: env.MAIL_FROM });
  return transport;
}

export async function sendMail(to: string, subject: string, text: string): Promise<void> {
  if (!env.SMTP_URL) {
    console.log(`[mail] to=${to} subject=${JSON.stringify(subject)}\n${text}`);
    return;
  }
  try {
    await smtp().sendMail({ from: env.MAIL_FROM, to, subject, text });
  } catch (e) {
    // Never log the URL: it carries the SMTP credentials.
    console.error(`[mail] sending to ${to} failed: ${(e as Error).message}`);
    throw new Error("couldn't send the email; try again later");
  }
}
