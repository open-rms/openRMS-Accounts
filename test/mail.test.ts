// SMTP delivery through nodemailer, against a local SMTP server (no network).
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { SMTPServer } from "smtp-server";

const received: { from?: string; to: string[]; data: string; user?: string }[] = [];
let server: SMTPServer;
let port = 0;

beforeAll(async () => {
  server = new SMTPServer({
    authOptional: false,
    disabledCommands: ["STARTTLS"],
    onAuth(auth, _s, cb) {
      cb(null, { user: auth.username });
    },
    onData(stream, session, cb) {
      let data = "";
      stream.on("data", (d) => (data += d));
      stream.on("end", () => {
        received.push({ from: session.envelope.mailFrom ? session.envelope.mailFrom.address : undefined, to: session.envelope.rcptTo.map((r) => r.address), data, user: session.user as string });
        cb();
      });
    },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  port = (server.server.address() as { port: number }).port;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe("sendMail", () => {
  it("logs instead of sending when SMTP_URL is unset", async () => {
    vi.resetModules();
    delete process.env.SMTP_URL;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { sendMail } = await import("../src/lib/mail.js");
    await sendMail("a@example.test", "Hi", "body");
    expect(log.mock.calls[0]?.[0]).toContain("to=a@example.test");
    log.mockRestore();
  });

  it("sends through SMTP with MAIL_FROM as the sender", async () => {
    vi.resetModules();
    process.env.SMTP_URL = `smtp://api_token:secret@127.0.0.1:${port}?ignoreTLS=true`;
    process.env.MAIL_FROM = "openRMS <noreply@mail.openrms.dev>";
    const { sendMail } = await import("../src/lib/mail.js");
    await sendMail("b@example.test", "Reset your openRMS password", "Reset: https://x");
    const m = received.at(-1)!;
    expect(m.user).toBe("api_token");
    expect(m.from).toBe("noreply@mail.openrms.dev");
    expect(m.to).toEqual(["b@example.test"]);
    expect(m.data).toContain("Subject: Reset your openRMS password");
  });

  it("hides SMTP details when sending fails", async () => {
    vi.resetModules();
    process.env.SMTP_URL = "smtp://api_token:supersecret@127.0.0.1:1?ignoreTLS=true&connectionTimeout=500";
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const { sendMail } = await import("../src/lib/mail.js");
    await expect(sendMail("c@example.test", "x", "y")).rejects.toThrow("couldn't send the email");
    expect(JSON.stringify(err.mock.calls)).not.toContain("supersecret");
    err.mockRestore();
  });
});
