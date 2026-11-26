import { env } from "../env.js";

/**
 * Mail sender. Without SMTP_URL configured, messages are logged to stdout so
 * development works without a mail server. Wire a real transport (nodemailer,
 * Cloudflare Email, etc.) here before enabling REQUIRE_EMAIL_VERIFICATION.
 */
export async function sendMail(to: string, subject: string, text: string): Promise<void> {
  if (!env.SMTP_URL) {
    console.log(`[mail] to=${to} subject=${JSON.stringify(subject)}\n${text}`);
    return;
  }
  throw new Error("SMTP transport not implemented yet: set up src/lib/mail.ts");
}
