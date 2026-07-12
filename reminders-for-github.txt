// Guardian Shield Training — automatic class reminders.
// Runs daily at 15:00 UTC (9:00 AM Mountain Daylight / 8:00 AM Mountain Standard).
// Sends each enrolled student a reminder one week before and the day before class.
import { getStore } from "@netlify/blobs";

const RESEND_KEY = process.env.RESEND_API_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "Guardian Shield Training <noreply@guardianshield.training>";

const store = () => getStore({ name: "guardian-data", consistency: "strong" });
async function readJson(key, fallback) {
  const v = await store().get(key);
  return v == null ? fallback : JSON.parse(v);
}
const writeJson = (key, value) => store().set(key, JSON.stringify(value));
const esc = (t) => String(t || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const uid = () => Math.random().toString(36).slice(2, 8).toUpperCase();
// note: changed flag below also covers token backfill

async function sendEmail(to, subject, bodyHtml) {
  const html = `<!doctype html><body style="margin:0;background:#12100C;padding:24px 12px;font-family:Georgia,serif;">
    <div style="max-width:560px;margin:0 auto;background:#1C1913;border:1px solid #3A3527;border-top:4px solid #C9A45C;">
      <div style="padding:22px 26px;border-bottom:1px solid #3A3527;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td style="padding-right:16px;vertical-align:middle;">
            <img src="https://guardianshield.training/email-logo.png" width="88" height="88" alt="Guardian Rapid Response Shield"
              style="display:block;width:88px;height:88px;border-radius:50%;border:3px solid #8F6F2E;" />
          </td>
          <td style="vertical-align:middle;">
            <div style="color:#C9A45C;font-size:11px;letter-spacing:3px;font-family:Courier,monospace;">GUARDIAN SHIELD TRAINING</div>
            <div style="color:#EAE3D2;font-size:22px;font-weight:bold;margin-top:6px;">${subject}</div>
          </td>
        </tr></table>
      </div>
      <div style="padding:22px 26px;color:#EAE3D2;font-size:15px;line-height:1.7;">${bodyHtml}</div>
      <div style="padding:14px 26px;border-top:1px solid #3A3527;color:#A29A85;font-size:12px;font-style:italic;">Protect what matters most. · guardianshield.training</div>
    </div></body>`;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: EMAIL_FROM, to: [to], subject, html }),
    });
    if (!r.ok) console.error("reminder email failed:", await r.json().catch(() => ({})));
    return r.ok;
  } catch (e) { console.error("reminder email error:", e); return false; }
}

function reminderBody(firstName, label, cls, place, lead, student) {
  const bring = cls.type === "instructor"
    ? "Bring a valid ID and your instructor approval details."
    : "Bring a valid ID and your own firearm for Day 1 live-fire training.";
  const needsForms = student && student.signToken && !student.waiverSignedAt;
  const formsBlock = needsForms ? `
    <p><strong>Action needed:</strong> your Range Safety Briefing and Liability Waiver must be signed before class. It takes about two minutes:</p>
    <p style="text-align:center;margin:20px 0 8px;">
      <a href="https://guardianshield.training/?sign=${student.signToken}"
         style="background:#C9A45C;color:#1A1509;text-decoration:none;font-weight:bold;font-size:15px;padding:13px 28px;border-radius:2px;display:inline-block;">Review &amp; Sign Required Forms &rarr;</a>
    </p>` : (student && student.waiverSignedAt ? `<p style="color:#6FBF8F;">✓ Your required forms are signed — nothing else needed before class.</p>` : "");
  return `
    <p>Hi ${esc(firstName)},</p>
    <p>${lead}</p>
    <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">
      <strong>${esc(label)}</strong><br>
      Date: ${esc(cls.date)} · ${esc(cls.time)}<br>
      Location: ${esc(place)}<br>
      Instructor: ${esc(cls.instructor)}
    </p>
    <p>${bring}</p>
    ${formsBlock}
    <p>Questions? Just reply to this email.</p>`;
}

export async function runReminders() {
  if (!RESEND_KEY) return { skipped: true, reason: "Email service not configured (RESEND_API_KEY missing)." };
  const today = new Date().toLocaleDateString("en-CA", { timeZone: "America/Denver" }); // YYYY-MM-DD, Utah time
  const classes = await readJson("gs:classes", []);
  let weekSent = 0, daySent = 0, changed = false;
  const summaries = [];

  for (const cls of classes) {
    if (cls.cancelled || cls.completed || !cls.date) continue;
    const students = (cls.enrolled || []).filter((s) => /@/.test(s.email || ""));
    if (!students.length) continue;
    for (const s of students) {                       // older registrations may predate signing links
      if (!s.signToken) { s.signToken = uid() + uid() + uid(); changed = true; }
    }
    const days = Math.round((Date.parse(cls.date) - Date.parse(today)) / 86400000);
    const place = [cls.location, [cls.city, cls.state].filter(Boolean).join(", ")].filter(Boolean).join(" — ");
    const label = cls.type === "instructor" ? "Instructor Certification Course" : "Guardian 2-Day Certification";

    if (days === 7 && !cls.reminder7SentAt) {
      for (const s of students) {
        const ok = await sendEmail(s.email, "Your Guardian training is one week away",
          reminderBody(s.name.split(" ")[0], label, cls, place, "A quick reminder — your training class is <strong>one week from today</strong>. Here are your details:", s));
        if (ok) weekSent += 1;
      }
      cls.reminder7SentAt = new Date().toISOString();
      changed = true;
      summaries.push(`1-week reminders sent to ${students.length} student${students.length === 1 ? "" : "s"} for ${cls.date} at ${place}.`);
    }

    if (days === 1 && !cls.reminder1SentAt) {
      for (const s of students) {
        const ok = await sendEmail(s.email, "Your Guardian training is tomorrow",
          reminderBody(s.name.split(" ")[0], label, cls, place, "See you tomorrow! Your training class starts <strong>tomorrow morning</strong>. Here are your details:", s));
        if (ok) daySent += 1;
      }
      cls.reminder1SentAt = new Date().toISOString();
      changed = true;
      summaries.push(`Day-before reminders sent to ${students.length} student${students.length === 1 ? "" : "s"} for ${cls.date} at ${place}.`);
    }
  }

  if (changed) {
    await writeJson("gs:classes", classes);
    const notices = await readJson("gs:notices", []);
    for (const text of summaries) {
      notices.unshift({ id: uid(), when: new Date().toLocaleString("en-US", { timeZone: "America/Denver" }), classId: "", read: false, text: `Automatic reminders — ${text}` });
    }
    await writeJson("gs:notices", notices);
  }

  return { ok: true, date: today, weekReminders: weekSent, dayReminders: daySent };
}

export default async () => {
  const result = await runReminders();
  console.log("reminders run:", JSON.stringify(result));
  return new Response(JSON.stringify(result), { headers: { "Content-Type": "application/json" } });
};

export const config = { schedule: "0 15 * * *" };
