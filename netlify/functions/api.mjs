// Guardian Shield Training — server API (Phase 1: server-side authentication)
// Handles: auth (signup/login/2FA/sessions), protected data access, and
// server-validated public actions (registration, applications, class requests,
// certificate verification). Data lives in Netlify Blobs.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import { runReminders } from "./reminders.mjs";

/* ================= configuration =================
   Set these in Netlify: Site configuration → Environment variables
   INSTRUCTOR_ENROLL_KEY  (default "SHIELD")
   ADMIN_ENROLL_KEY       (default "ADMIN")
   DEMO_MODE              set to "false" to stop returning demo 2FA codes */
const INSTRUCTOR_KEY = (process.env.INSTRUCTOR_ENROLL_KEY || "SHIELD").toUpperCase();
const ADMIN_KEY = (process.env.ADMIN_ENROLL_KEY || "ADMIN").toUpperCase();
const DEMO_MODE = process.env.DEMO_MODE !== "false";
const SUPERUSER = (process.env.SUPERUSER_EMAIL || "aaron@citizenarmor.com").toLowerCase();
const isSuper = (sess) => !!sess && sess.role === "admin" && (sess.email || "").toLowerCase() === SUPERUSER;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY || "";
const RESEND_KEY = process.env.RESEND_API_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "Guardian Shield Training <noreply@guardianshield.training>";
const ADMIN_NOTIFY = process.env.ADMIN_NOTIFY_EMAIL || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const SESSION_HOURS = 12;

const store = () => getStore({ name: "guardian-data", consistency: "strong" });
const json = (data, status = 200) => Response.json(data, { status });
const bad = (error, status = 400) => json({ error }, status);

/* ================= crypto helpers ================= */
const randomToken = () => crypto.randomBytes(32).toString("hex");
const newSalt = () => crypto.randomBytes(16).toString("hex");
const hashPassword = (password, salt) =>
  crypto.scryptSync(password, salt, 64).toString("hex");
const safeEqual = (a, b) => {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
};

/* TOTP (RFC 6238, SHA-1, 30s window) */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const makeTotpSecret = () => {
  const bytes = crypto.randomBytes(20);
  let bits = "", out = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
};
const b32decode = (s) => {
  let bits = "";
  for (const ch of s.replace(/=+$/, "").toUpperCase()) {
    const v = B32.indexOf(ch);
    if (v >= 0) bits += v.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
};
const totpAt = (secret, counter) => {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(counter, 4);
  const h = crypto.createHmac("sha1", b32decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const code = (((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1000000;
  return String(code).padStart(6, "0");
};
const verifyTotp = (secret, code) => {
  const t = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some((w) => totpAt(secret, t + w) === String(code).trim());
};
const sixDigits = () => String(crypto.randomInt(100000, 1000000));
const uid = () => crypto.randomBytes(4).toString("hex").toUpperCase().slice(0, 6);

/* ================= blob helpers ================= */
async function readJson(key, fallback) {
  const v = await store().get(key);
  return v == null ? fallback : JSON.parse(v);
}
const writeJson = (key, value) => store().set(key, JSON.stringify(value));

/* ================= accounts & sessions ================= */
const getAccounts = () => readJson("auth:accounts", []);
const saveAccounts = (a) => writeJson("auth:accounts", a);
const findAccount = (accounts, email) =>
  accounts.find((a) => a.email.toLowerCase() === String(email || "").trim().toLowerCase());

async function createSession(account) {
  const token = randomToken();
  await writeJson(`sess:${token}`, {
    email: account.email, role: account.role, name: account.name,
    company: account.company || "", expires: Date.now() + SESSION_HOURS * 3600 * 1000,
  });
  return token;
}
async function getSession(req) {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const sess = await readJson(`sess:${token}`, null);
  if (!sess || sess.expires < Date.now()) return null;
  return { ...sess, token };
}
const publicAccount = (a) => ({ id: a.id, role: a.role, name: a.name, company: a.company || "", email: a.email, phone: a.phone || "" });

/* ================= public data sanitizers ================= */
const sanitizeClasses = (classes) =>
  (classes || []).map((c) => ({ ...c, enrolled: [], enrolledCount: (c.enrolled || []).length }));

const SEED_CLASSES = [
  { id: "GS-A1B2C3", type: "standard", date: "2026-08-08", time: "8:00 AM", location: "Wasatch Range Training Center", city: "Salt Lake City", state: "UT", seats: 12, price: 495, instructor: "M. Reyes", enrolled: [], completed: false },
  { id: "GS-D4E5F6", type: "standard", date: "2026-08-22", time: "8:00 AM", location: "High Desert Tactical", city: "Boise", state: "ID", seats: 10, price: 495, instructor: "K. Donnelly", enrolled: [], completed: false },
  { id: "GS-G7H8I9", type: "instructor", date: "2026-09-12", time: "7:30 AM", location: "Guardian HQ", city: "Denver", state: "CO", seats: 8, price: 1250, instructor: "Lead Cadre", enrolled: [], completed: false },
];

/* ================= required forms (versioned) ================= */
const DOC_VERSION = "2026-07-12";
const RANGE_BRIEFING = [
  ["Universal Firearm Safety Rules", "1. Treat every firearm as if it is loaded at all times. 2. Never point the muzzle at anything you are not willing to destroy. 3. Keep your finger off the trigger and outside the trigger guard until your sights are on target and you have made the decision to shoot. 4. Be sure of your target, what is in line with it, and what is beyond it."],
  ["Range Commands", "All participants must know and obey these commands immediately: \"RANGE IS HOT\" — shooting may begin; \"CEASE FIRE\" — stop shooting immediately, remove finger from trigger, hold position and await instruction (anyone may call a cease fire at any time for a safety concern); \"UNLOAD AND SHOW CLEAR\" — remove magazine, lock slide/action open, present for inspection; \"RANGE IS COLD\" — firearms benched and untouched, actions open, no handling while anyone is downrange."],
  ["Muzzle and Handling Discipline", "Muzzles remain pointed downrange or in a designated safe direction at all times. Firearms are loaded only on the firing line on the instructor's command. Never handle a firearm while anyone is forward of the firing line. If a firearm malfunctions, keep it pointed downrange and raise your support hand for an instructor."],
  ["Personal Protective Equipment", "Eye protection and hearing protection are mandatory for everyone on or near the range whenever the range is hot. Closed-toe footwear is required. Hats with brims and high-neck shirts are strongly recommended to protect against ejected brass."],
  ["Physical and Medical Readiness", "Participants must not be under the influence of alcohol, cannabis, or any drug or medication that impairs judgment or coordination. Inform an instructor privately before training of any medical condition that could affect your safe participation (including pregnancy, heart conditions, seizure disorders, or recent injuries)."],
  ["Instructor Authority", "The Range Safety Officer and instructors have final authority on all safety matters. Any participant may be removed from the range, without refund, for unsafe firearm handling, failure to follow commands, or conduct that endangers any person."],
];
const LIABILITY_WAIVER = [
  ["Acknowledgment of Inherent Risk", "I understand that participation in the Guardian Rapid Response Shield training program (the \"Program\"), operated by The Armored Citizen, LLC dba Guardian Shield Training (the \"Company\"), involves live-fire firearms training, physical movement, simulated defensive scenarios, and the use of ballistic protective equipment. I acknowledge that these activities carry inherent risks that cannot be eliminated regardless of the care taken, including but not limited to: discharge of firearms, ricochet, flying debris and ejected casings, hearing or vision damage, physical injury from movement or falls, equipment failure, and, in extreme cases, permanent disability or death."],
  ["Voluntary Assumption of Risk", "I am participating in the Program voluntarily. I knowingly and freely assume all risks of injury, illness, damage, or loss, both known and unknown, arising from or related to my participation, even if arising from the negligence of the Company, its owners, employees, instructors, agents, or other participants, and I assume full responsibility for my participation."],
  ["Release and Waiver of Liability", "In consideration of being permitted to participate, I, for myself and on behalf of my heirs, assigns, personal representatives, and next of kin, hereby release, indemnify, and hold harmless the Company, its owners, members, officers, employees, instructors, contractors, and agents, and the owners and operators of the facility at which training occurs, from and against any and all claims, demands, losses, damages, and causes of action of any kind arising out of or related to my participation in the Program, to the fullest extent permitted by law."],
  ["Firearm Competency and Legal Eligibility", "I represent that I am at least 18 years of age (21 where required for the firearm used), that I am legally permitted to possess and handle the firearm I bring to training under all applicable federal, state, and local laws, and that any firearm and ammunition I bring is in safe working condition."],
  ["Medical Treatment Authorization", "I authorize the Company and its instructors to secure emergency medical treatment on my behalf if I am injured and unable to direct my own care. I understand I am financially responsible for any such treatment."],
  ["Rules Compliance", "I agree to comply with the Range Safety Briefing, all posted facility rules, and all instructions given by instructors and Range Safety Officers. I understand that failure to comply may result in immediate removal from the Program without refund."],
  ["Severability and Governing Law", "If any portion of this agreement is held invalid, the remainder shall continue in full force and effect. This agreement is governed by the laws of the State of Utah."],
  ["Electronic Signature Consent", "I consent to sign this document electronically and agree that my electronic signature, together with the recorded date, time, and network details of my submission, has the same legal effect as a handwritten signature."],
];

/* ================= Instructor Agreement (versioned) ================= */
const AGREEMENT_VERSION = "2026-07-12";
const INSTRUCTOR_AGREEMENT = [
  ["Engagement", "This Instructor Agreement (the \"Agreement\") is between The Armored Citizen, LLC dba Guardian Shield Training (the \"Company\") and the undersigned instructor (the \"Instructor\"). The Company engages the Instructor to deliver Guardian Rapid Response Shield certification training to registered students at classes scheduled through the Company's platform."],
  ["Certification Requirement", "The Instructor must hold and maintain a current Guardian Instructor certification issued through the Company's Instructor Certification Course. Certification lapses, revocation, or failure to maintain program standards suspends this Agreement automatically until certification is restored."],
  ["Independent Contractor Status", "The Instructor is an independent contractor, not an employee, partner, or agent of the Company. The Instructor controls the manner and means of delivering instruction within program safety standards, provides their own transportation, and is not entitled to employee benefits. The Instructor is solely responsible for all federal, state, and local taxes on compensation received, and must provide the Company a completed IRS Form W-9 before receiving any payment. The Company will report payments as required by law, including on IRS Form 1099-NEC where applicable."],
  ["Compensation", "The Instructor is compensated by commission on paid student registrations for classes they instruct, at the per-student rates recorded in the Company's commission system, as amended from time to time with notice. Commissions are payable per the Company's payout schedule, accompanied by an itemized commission statement. No commission is owed on refunded or cancelled registrations."],
  ["Safety Standards and Conduct", "The Instructor agrees to conduct all training in accordance with the Company's Range Safety Briefing, program curriculum, and all applicable laws and facility rules; to verify that every participating student has a signed Range Safety Briefing and Liability Waiver before live-fire participation; and to hold final on-range safety authority, including removing unsafe participants. The Instructor will immediately report any injury, discharge-related incident, or near miss to the Company."],
  ["Insurance", "The Instructor is strongly encouraged, and may be required upon notice, to maintain professional liability insurance covering firearms instruction, and shall provide proof of coverage on request."],
  ["Brand Use", "The Company grants the Instructor a limited, revocable, non-exclusive license to use the Guardian Shield Training name and marks solely to promote and deliver classes scheduled through the Company's platform. All goodwill inures to the Company. This license ends with this Agreement."],
  ["Confidentiality", "The Instructor will not disclose or misuse non-public Company information, including student personal information, pricing, commission structures, and training materials, during or after the term of this Agreement, except as required by law."],
  ["Indemnification", "Each party shall indemnify the other against third-party claims arising from its own negligence or willful misconduct. The Instructor additionally agrees to indemnify the Company against claims arising from instruction delivered outside program safety standards or outside the scope of this Agreement."],
  ["Term and Termination", "This Agreement begins on the date signed and continues until terminated. Either party may terminate with thirty (30) days' written notice. The Company may terminate immediately for safety violations, loss of certification, unlawful conduct, or material breach. Earned, unpaid commissions for completed classes survive termination."],
  ["General", "This Agreement is the entire agreement between the parties on its subject, supersedes prior discussions, may be amended only in writing, and is governed by the laws of the State of Utah. If any provision is held invalid, the remainder continues in effect."],
  ["Electronic Signature Consent", "The Instructor consents to executing this Agreement electronically and agrees that their electronic signature, with the recorded date, time, and network details, has the same legal effect as a handwritten signature."],
];

/* ================= email (Resend) ================= */
async function sendEmail(to, subject, bodyHtml, attachments = null) {
  if (!RESEND_KEY) return { skipped: true };
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
      body: JSON.stringify({ from: EMAIL_FROM, to: Array.isArray(to) ? to : [to], subject, html, ...(attachments && attachments.length ? { attachments } : {}) }),
    });
    const j = await r.json();
    if (!r.ok) { console.error("email send failed:", j); return { error: j.message || "send failed" }; }
    return { id: j.id };
  } catch (e) { console.error("email error:", e); return { error: String(e) }; }
}
const esc = (t) => String(t || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/* ================= Stripe helpers ================= */
async function stripeReq(path, params) {
  const body = new URLSearchParams();
  const add = (k, v) => body.append(k, String(v));
  const flatten = (obj, prefix = "") => {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}[${k}]` : k;
      if (v !== null && typeof v === "object") flatten(v, key);
      else add(key, v);
    }
  };
  flatten(params);
  const r = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${STRIPE_SECRET}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error?.message || "Stripe request failed");
  return j;
}

function verifyStripeSignature(payload, sigHeader, secret) {
  try {
    const parts = Object.fromEntries(sigHeader.split(",").map((kv) => kv.split("=")));
    const t = Number(parts.t);
    if (!t || Math.abs(Date.now() / 1000 - t) > 300) return false; // 5-minute tolerance
    const expected = crypto.createHmac("sha256", secret).update(`${parts.t}.${payload}`).digest("hex");
    return safeEqual(expected, parts.v1 || "");
  } catch (e) { return false; }
}

/* Shared finalizer: records an enrollment + notification (used by demo,
   free-with-discount, and Stripe webhook paths). */
async function finalizeRegistration({ classId, student, discountCode, passcode, paidAmount, paymentRef, creditFrom = "" }) {
  const classes = await readJson("gs:classes", []);
  const cls = classes.find((c) => c.id === classId);
  if (!cls) return { error: "Class not found." };

  if (cls.type === "instructor" && passcode) {
    const apps = await readJson("gs:apps", []);
    const t = String(passcode).trim().toUpperCase();
    const match = apps.find((a) => a.passcode && a.passcode.toUpperCase() === t);
    if (match) { match.passcodeUsed = true; match.passcodeUsedAt = new Date().toISOString(); await writeJson("gs:apps", apps); }
  }
  if (discountCode) {
    const codes = await readJson("gs:codes", []);
    const k = codes.find((c) => c.code.toUpperCase() === String(discountCode).toUpperCase());
    if (k) { k.uses = (k.uses || 0) + 1; await writeJson("gs:codes", codes); }
  }

  const record = {
    name: student.name.trim(), email: student.email.trim(), phone: (student.phone || "").trim(),
    company: (student.company || "").trim(),
    ref: "REG-" + uid(), registeredAt: new Date().toISOString(),
    signToken: uid() + uid() + uid(),
    discountCode: discountCode || "", paid: paidAmount,
    ...(paymentRef ? { paymentRef } : {}),
    ...(creditFrom ? { creditFrom } : {}),
  };
  cls.enrolled = [...(cls.enrolled || []), record];
  await writeJson("gs:classes", classes);

  const notices = await readJson("gs:notices", []);
  const place = [cls.location, [cls.city, cls.state].filter(Boolean).join(", ")].filter(Boolean).join(" — ");
  notices.unshift({
    id: uid(), when: new Date().toLocaleString(), classId: cls.id, read: false,
    text: `New registration — ${record.name} (${record.email}) enrolled in the ${cls.type === "instructor" ? "Instructor Course" : "2-Day Certification"} scheduled for ${cls.date} at ${place}. ${creditFrom ? `Registered with no-show credit from ${creditFrom} — no new payment.` : `Paid $${paidAmount.toFixed(2)}${discountCode ? ` (code ${discountCode})` : ""}${paymentRef ? " via Stripe" : ""}.`}`,
  });
  await writeJson("gs:notices", notices);

  /* ---- Phase 3: emails (best-effort; never blocks the registration) ---- */
  try {
    const typeLabel = cls.type === "instructor" ? "Instructor Certification Course" : "Guardian 2-Day Certification";
    await sendEmail(record.email, "Registration confirmed", `
      <p>Hi ${esc(record.name.split(" ")[0])},</p>
      <p>Your seat is reserved. Here are your details:</p>
      <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">
        <strong>${esc(typeLabel)}</strong><br>
        Date: ${esc(cls.date)} · ${esc(cls.time)}<br>
        Location: ${esc(place)}<br>
        Instructor: ${esc(cls.instructor)}<br>
        ${creditFrom ? `Payment: covered by your no-show credit (${esc(creditFrom)}) — nothing due` : `Amount paid: $${paidAmount.toFixed(2)}${discountCode ? ` (code ${esc(discountCode)})` : ""}`}<br>
        Registration reference: <strong style="color:#C9A45C;">${record.ref}</strong>
      </p>
      <p style="font-size:12px;color:#A99F86;"><strong>Please note:</strong> all registrations are final — no refunds. If you're unable to attend, your paid registration converts to a one-time credit toward a future class of the same type; keep your registration reference above.</p>
      <p>Bring a valid ID${cls.type === "instructor" ? "" : " and your own firearm for Day 1 live-fire training"}.</p>
      <p><strong>Required before class:</strong> please review and electronically sign your Range Safety Briefing and Liability Waiver:</p>
      <p style="text-align:center;margin:20px 0 8px;">
        <a href="https://guardianshield.training/?sign=${record.signToken}"
           style="background:#C9A45C;color:#1A1509;text-decoration:none;font-weight:bold;font-size:15px;padding:13px 28px;border-radius:2px;display:inline-block;">Review &amp; Sign Required Forms &rarr;</a>
      </p>`);

    const accounts = await getAccounts();
    const instr = accounts.find((a) => a.role === "instructor" && a.name.toLowerCase() === (cls.instructor || "").toLowerCase());
    const alertHtml = `
      <p>A new student registered for your class:</p>
      <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">
        <strong>${esc(record.name)}</strong> · ${esc(record.email)}${record.phone ? " · " + esc(record.phone) : ""}${record.company ? "<br>Company: " + esc(record.company) : ""}<br>
        ${esc(typeLabel)} — ${esc(cls.date)} at ${esc(place)}<br>
        Paid $${paidAmount.toFixed(2)} · Ref ${record.ref}
      </p>
      <p>The full roster is in your Instructor Portal.</p>`;
    if (instr) await sendEmail(instr.email, "New class registration", alertHtml);
    if (ADMIN_NOTIFY && (!instr || instr.email.toLowerCase() !== ADMIN_NOTIFY.toLowerCase())) await sendEmail(ADMIN_NOTIFY, "New class registration", alertHtml);
  } catch (e) { console.error("registration email error:", e); }

  return { ok: true, ref: record.ref };
}

/* Validates a registration request; returns { cls, paid, appliedCode } or { error } */
async function validateRegistration({ classId, student, discountCode, passcode }) {
  if (!student?.name?.trim() || !/@/.test(student?.email || "")) return { error: "Name and a valid email are required." };
  if (String(student?.phone || "").replace(/\D/g, "").length < 10) return { error: "A mobile phone number is required." };
  const classes = await readJson("gs:classes", []);
  const cls = classes.find((c) => c.id === classId);
  if (!cls || cls.completed || cls.cancelled) return { error: "That class is not open for registration." };
  if ((cls.enrolled || []).length >= cls.seats) return { error: "That class is full." };

  if (cls.type === "instructor") {
    const apps = await readJson("gs:apps", []);
    const t = String(passcode || "").trim().toUpperCase();
    const match = apps.find((a) => a.passcode && a.passcode.toUpperCase() === t);
    if (!match || match.status !== "approved") return { error: "A valid instructor approval passcode is required." };
    if (match.passcodeUsed) return { error: "That passcode has already been used." };
  }

  let paid = cls.price, appliedCode = "";
  if (discountCode) {
    const codes = await readJson("gs:codes", []);
    const t = String(discountCode).trim().toUpperCase();
    const k = codes.find((c) => c.code.toUpperCase() === t);
    const expired = k?.expires && new Date(k.expires + "T23:59:59") < new Date();
    const usedUp = k?.maxUses && (k.uses || 0) >= Number(k.maxUses);
    if (k && k.active && !expired && !usedUp && (k.scope || "classes") !== "store") {
      const discount = k.kind === "percent"
        ? Math.round(cls.price * Math.min(Number(k.value), 100)) / 100
        : Math.min(Number(k.value), cls.price);
      paid = Math.max(0, Math.round((cls.price - discount) * 100) / 100);
      appliedCode = k.code.toUpperCase();
    }
  }
  return { cls, paid, appliedCode };
}

/* ================= route handlers ================= */
async function handleAuth(req, path, body) {
  /* ---- signup: validate, stage pending, return TOTP secret ---- */
  if (path === "signup") {
    const { role, name, company, email, phone, password, enrollKey } = body;
    if (!["instructor", "admin"].includes(role)) return bad("Invalid role.");
    if (!name?.trim()) return bad("Enter your name.");
    if (!/@/.test(email || "")) return bad("Enter a valid email address.");
    if ((password || "").length < 8) return bad("Password must be at least 8 characters.");
    let inviteRecord = null;
    if (body.inviteToken) {
      inviteRecord = await readJson(`gs:admininvite:${body.inviteToken}`, null);
      if (!inviteRecord || inviteRecord.usedAt) return bad("That invitation link has already been used or is invalid.");
      if (inviteRecord.expires < Date.now()) return bad("That invitation link has expired — ask for a new one.");
      if ((inviteRecord.role || "admin") !== role) return bad("This invitation is for a different account type.");
      if (inviteRecord.email.toLowerCase() !== String(email || "").trim().toLowerCase()) return bad(`This invitation was issued to ${inviteRecord.email}. Sign up with that email address.`);
    } else if (role === "admin") {
      if (String(enrollKey || "").trim().toUpperCase() !== ADMIN_KEY) return bad("Invalid enrollment key.");
    } else {
      /* instructors sign up with their personal Instructor Certification Number */
      const certNo = String(enrollKey || "").trim().toUpperCase();
      if (!certNo) return bad("Enter your Instructor Certification Number.");
      const certsAll = await readJson("gs:certs", []);
      const cert = certsAll.find((c) => (c.certId || "").toUpperCase() === certNo && c.type === "instructor");
      if (!cert) return bad("That Instructor Certification Number wasn't found. Check your certificate or congratulations email.");
      if ((cert.email || "").toLowerCase() !== String(email || "").trim().toLowerCase()) {
        return bad(`That certification was issued to a different email address. Sign up with the email on your certification (${cert.email.replace(/(.).*(@.*)/, "$1***$2")}).`);
      }
    }
    const accounts = await getAccounts();
    if (findAccount(accounts, email)) return bad("An account with that email already exists.");
    const salt = newSalt();
    const pendingToken = randomToken();
    const pending = {
      type: "signup", expires: Date.now() + 15 * 60 * 1000,
      inviteToken: role === "admin" && body.inviteToken ? body.inviteToken : null,
      account: {
        id: uid(), role, name: name.trim(), company: (company || "").trim(),
        email: email.trim(), phone: (phone || "").trim(),
        certId: role === "instructor" ? String(enrollKey || "").trim().toUpperCase() : "",
        salt, hash: hashPassword(password, salt),
        totpSecret: makeTotpSecret(), twofa: "totp",
        created: new Date().toISOString().slice(0, 10),
      },
    };
    await writeJson(`auth:pending:${pendingToken}`, pending);
    return json({
      pendingToken,
      totpSecret: pending.account.totpSecret,
    });
  }

  /* ---- finish signup after 2FA proof ---- */
  if (path === "verify-setup") {
    const { pendingToken, code, method } = body;
    const pending = await readJson(`auth:pending:${pendingToken}`, null);
    if (!pending || pending.type !== "signup" || pending.expires < Date.now()) return bad("Setup expired — start again.", 410);
    const ok = verifyTotp(pending.account.totpSecret, code);
    if (!ok) return bad("That code didn't match. Try again.", 401);
    const account = { ...pending.account, twofa: "totp" };
    const accounts = await getAccounts();
    if (findAccount(accounts, account.email)) return bad("An account with that email already exists.");
    await saveAccounts([...accounts, account]);
    if (pending.inviteToken) {
      const inv = await readJson(`gs:admininvite:${pending.inviteToken}`, null);
      if (inv) { inv.usedAt = new Date().toISOString(); inv.usedBy = account.email; await writeJson(`gs:admininvite:${pending.inviteToken}`, inv); }
    }
    await store().delete(`auth:pending:${pendingToken}`);
    /* alert the program director when a new instructor joins the portal */
    if (account.role === "instructor" && ADMIN_NOTIFY && account.email.toLowerCase() !== ADMIN_NOTIFY.toLowerCase()) {
      try {
        await sendEmail(ADMIN_NOTIFY, "New instructor account created", `
          <p><strong>${esc(account.name)}</strong>${account.company ? " (" + esc(account.company) + ")" : ""} just created their Instructor Portal account.</p>
          <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">${esc(account.email)}${account.phone ? " · " + esc(account.phone) : ""}${account.certId ? "<br>Certification: " + esc(account.certId) : ""}</p>
          <p>Their account is active — they can now create classes and access instructor resources.</p>`);
      } catch (e) { console.error("account alert email error:", e); }
    }
    const token = await createSession(account);
    return json({ session: token, account: publicAccount(account) });
  }

  /* ---- login step 1: password ---- */
  if (path === "login") {
    const { role, email, password } = body;
    const accounts = await getAccounts();
    const account = findAccount(accounts, email);
    if (!account || account.role !== role) return bad("No account found with that email.", 401);
    if (!safeEqual(hashPassword(password || "", account.salt), account.hash)) return bad("Incorrect password.", 401);
    const pendingToken = randomToken();
    await writeJson(`auth:pending:${pendingToken}`, {
      type: "login", email: account.email, expires: Date.now() + 10 * 60 * 1000,
    });
    return json({ pendingToken, twofa: "totp" });
  }

  /* ---- login step 2: 2FA ---- */
  if (path === "verify-login") {
    const { pendingToken, code, method } = body;
    const pending = await readJson(`auth:pending:${pendingToken}`, null);
    if (!pending || pending.type !== "login" || pending.expires < Date.now()) return bad("Sign-in expired — start again.", 410);
    const accounts = await getAccounts();
    const account = findAccount(accounts, pending.email);
    if (!account) return bad("Account not found.", 401);
    const ok = verifyTotp(account.totpSecret, code);
    if (!ok) return bad("That code didn't match. Try again.", 401);
    await store().delete(`auth:pending:${pendingToken}`);
    const token = await createSession(account);
    return json({ session: token, account: publicAccount(account) });
  }

  /* ---- password reset, step 1: identify the account ---- */
  if (path === "reset-start") {
    const { role, email } = body;
    const accounts = await getAccounts();
    const account = findAccount(accounts, email);
    if (!account || account.role !== role) return bad("No account found with that email.", 404);
    const pendingToken = randomToken();
    const emailCode = sixDigits();
    await writeJson(`auth:pending:${pendingToken}`, {
      type: "reset", email: account.email, emailCode, expires: Date.now() + 10 * 60 * 1000,
    });
    let emailSent = false;
    if (RESEND_KEY) {
      const result = await sendEmail(account.email, "Your password reset code", `
        <p>Hi ${esc(account.name.split(" ")[0])},</p>
        <p>Use this code to reset your Guardian Shield Training password. It expires in 10 minutes.</p>
        <p style="background:#242017;border:1px solid #C9A45C;padding:14px 16px;text-align:center;font-family:Courier,monospace;font-size:24px;color:#E3CD96;letter-spacing:6px;">${emailCode}</p>
        <p>If you didn't request this, you can safely ignore this email — your password is unchanged.</p>`);
      emailSent = !result.error && !result.skipped;
    }
    return json({ pendingToken, twofa: "totp", emailSent });
  }

  /* ---- password reset, step 2: prove identity with 2FA, set new password ---- */
  if (path === "reset-complete") {
    const { pendingToken, code, method, newPassword } = body;
    const pending = await readJson(`auth:pending:${pendingToken}`, null);
    if (!pending || pending.type !== "reset" || pending.expires < Date.now()) return bad("Reset expired — start again.", 410);
    if ((newPassword || "").length < 8) return bad("New password must be at least 8 characters.");
    const accounts = await getAccounts();
    const account = findAccount(accounts, pending.email);
    if (!account) return bad("Account not found.", 404);
    const ok = (method === "email" || method === "sms")
      ? safeEqual(String(code).trim(), pending.emailCode || pending.smsCode)
      : verifyTotp(account.totpSecret, code);
    if (!ok) return bad("That code didn't match. Try again.", 401);
    account.salt = newSalt();
    account.hash = hashPassword(newPassword, account.salt);
    await saveAccounts(accounts);
    await store().delete(`auth:pending:${pendingToken}`);
    return json({ ok: true });
  }

  /* ---- admin: list all accounts (never exposes secrets) ---- */
  if (path === "accounts") {
    const sess = await getSession(req);
    if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
    const accounts = await getAccounts();
    return json({ accounts: accounts.map((a) => ({ ...publicAccount(a), twofa: a.twofa, created: a.created, agreementSignedAt: a.agreementSignedAt || null, w9UploadedAt: a.w9UploadedAt || null, w9Name: a.w9Name || "" })) });
  }

  /* ---- admin: set a temporary password for any account ---- */
  if (path === "admin-set-password") {
    const sess = await getSession(req);
    if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
    const { email, newPassword } = body;
    if ((newPassword || "").length < 8) return bad("Password must be at least 8 characters.");
    const accounts = await getAccounts();
    const account = findAccount(accounts, email);
    if (!account) return bad("No account found with that email.", 404);
    account.salt = newSalt();
    account.hash = hashPassword(newPassword, account.salt);
    await saveAccounts(accounts);
    return json({ ok: true });
  }

  /* ---- break-glass: rotate an account's 2FA secret (requires RECOVERY_KEY env var) ---- */
  if (path === "recover-2fa") {
    const RK = process.env.RECOVERY_KEY;
    if (!RK) return bad("Recovery is not enabled. Set a RECOVERY_KEY environment variable in Netlify to enable it.", 403);
    const { email, password, recoveryKey } = body;
    if (!recoveryKey || !safeEqual(String(recoveryKey), String(RK))) return bad("Recovery key doesn't match.", 403);
    const accounts = await getAccounts();
    const account = findAccount(accounts, email);
    if (!account) return bad("No account found with that email.", 404);
    if (!safeEqual(hashPassword(password || "", account.salt), account.hash)) return bad("Incorrect password.", 401);
    account.totpSecret = makeTotpSecret();
    account.twofa = "totp";
    await saveAccounts(accounts);
    try {
      await sendEmail(account.email, "Your two-factor authentication was reset", `
        <p>Hi ${esc((account.name || "").split(" ")[0] || "there")},</p>
        <p>The authenticator (two-factor) setup for your Guardian Shield Training account was just reset using the site's recovery key. A new setup key was issued and the old authenticator entry no longer works.</p>
        <p>If this was you, no action is needed. If it wasn't, contact the site administrator immediately.</p>`);
      if (ADMIN_NOTIFY && ADMIN_NOTIFY.toLowerCase() !== account.email.toLowerCase()) {
        await sendEmail(ADMIN_NOTIFY, "2FA recovery used", `<p>The recovery key was used to reset two-factor authentication for <strong>${esc(account.email)}</strong>.</p>`);
      }
    } catch (e) { console.error("recovery email error:", e); }
    return json({ ok: true, totpSecret: account.totpSecret, email: account.email });
  }


/* ================= Instructor Certificate PDF ================= */
const CERT_LOGO_JPEG = "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"; // 420x420
const CERT_SIG_JPEG = "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"; // 620x134, Aaron K. Gilbert

function buildInstructorCertPdf({ name, certId, issued, expires, type = "instructor" }) {
  const isInstr = type === "instructor";
  const W = 792, H = 612; // US Letter landscape, points
  const bronze = "0.561 0.435 0.180", ink = "0.169 0.141 0.082", gray = "0.353 0.306 0.200";
  const escPdf = (t) => String(t || "").replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
  const widthOf = (t, size, factor, tc = 0) => t.length * size * factor + Math.max(0, t.length - 1) * tc;
  const center = (t, size, font, factor, y, color, tc = 0) =>
    `BT /${font} ${size} Tf ${tc} Tc ${color} rg ${(W - widthOf(t, size, factor, tc)) / 2} ${y} Td (${escPdf(t)}) Tj ET\n`;
  const at = (t, size, font, x, y, color, tc = 0) =>
    `BT /${font} ${size} Tf ${tc} Tc ${color} rg ${x} ${y} Td (${escPdf(t)}) Tj ET\n`;
  const rightAt = (t, size, factor, font, xRight, y, color, tc = 0) =>
    at(t, size, font, xRight - widthOf(t, size, factor, tc), y, color, tc);

  const bodyLines = isInstr ? [
    "has successfully completed the Guardian Rapid Response Shield Instructor Certification Course,",
    "demonstrating mastery of the full curriculum, live-fire coaching methods, and structure-clearing",
    "instruction, and is authorized to teach the two-day certification program.",
  ] : [
    "has successfully completed the two-day Guardian Rapid Response Shield certification course,",
    "including live-fire training and in-building scenario evaluation, and has met the Guardian",
    "standard for shield deployment and defensive movement.",
  ];
  const fmt = (d) => { try { const [y, m, dd] = String(d).split("-"); return `${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][Number(m)-1]} ${Number(dd)}, ${y}`; } catch (e) { return d; } };

  let c = "";
  c += `${bronze} RG 3 w 24 24 ${W - 48} ${H - 48} re S\n`;
  c += `${bronze} RG 0.8 w 34 34 ${W - 68} ${H - 68} re S\n`;
  const logoW = 92;
  c += `q ${logoW} 0 0 ${logoW} ${(W - logoW) / 2} ${H - 62 - logoW} cm /Im1 Do Q\n`;
  c += center("GUARDIAN RAPID RESPONSE SHIELD", 13, "F2", 0.55, H - 178, bronze, 2.4);
  c += center(isInstr ? "CERTIFIED INSTRUCTOR" : "CERTIFIED GRADUATE", 24, "F2", 0.55, H - 210, ink, 3.2);
  c += center("This certifies that", 13, "F5", 0.48, H - 246, gray);
  const nameSize = name.length > 26 ? 24 : 30;
  c += center(name, nameSize, "F4", 0.5, H - 284, ink);
  const nw = Math.max(widthOf(name, nameSize, 0.5), 260);
  c += `${bronze} RG 0.8 w ${(W - nw) / 2 - 14} ${H - 292} m ${(W + nw) / 2 + 14} ${H - 292} l S\n`;
  bodyLines.forEach((ln, i) => { c += center(ln, 11, "F3", 0.485, H - 322 - i * 16, ink); });

  // signature block — Program Director only
  const sigW = 158, sigH = Math.round(sigW * 134 / 620);
  c += `q ${sigW} 0 0 ${sigH} ${(W - sigW) / 2} 158 cm /Im2 Do Q\n`;
  c += `${ink} RG 0.8 w ${(W - 200) / 2} 154 m ${(W + 200) / 2} 154 l S\n`;
  c += center("Aaron K. Gilbert", 13, "F3", 0.48, 138, ink);
  c += center("PROGRAM DIRECTOR", 8, "F6", 0.6, 124, bronze, 1.4);

  c += at("CERTIFICATE NO.", 8, "F6", 66, 176, bronze, 0.8);
  c += at(certId, 13, "F6", 66, 158, ink);
  c += rightAt("ISSUED / EXPIRES", 8, 0.6, "F6", W - 66, 176, bronze, 0.8);
  c += rightAt(`${fmt(issued)}  -  ${fmt(expires)}`, 11, 0.6, "F6", W - 66, 158, ink);
  c += center("Verify this certification any time at guardianshield.training/?view=verify", 8.5, "F6", 0.6, 56, gray);

  const logoBytes = Buffer.from(CERT_LOGO_JPEG, "base64");
  const sigBytes = Buffer.from(CERT_SIG_JPEG, "base64");
  const contentBytes = Buffer.from(c, "latin1");
  const objs = [];
  objs.push(`<< /Type /Catalog /Pages 2 0 R >>`);
  objs.push(`<< /Type /Pages /Kids [3 0 R] /Count 1 >>`);
  objs.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F2 7 0 R /F3 8 0 R /F4 9 0 R /F5 10 0 R /F6 11 0 R >> /XObject << /Im1 5 0 R /Im2 6 0 R >> >> /Contents 4 0 R >>`);
  objs.push({ dict: `<< /Length ${contentBytes.length} >>`, stream: contentBytes });
  objs.push({ dict: `<< /Type /XObject /Subtype /Image /Width 420 /Height 420 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${logoBytes.length} >>`, stream: logoBytes });
  objs.push({ dict: `<< /Type /XObject /Subtype /Image /Width 620 /Height 134 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${sigBytes.length} >>`, stream: sigBytes });
  ["Helvetica-Bold", "Times-Roman", "Times-Bold", "Times-Italic", "Courier"].forEach((f) => {
    objs.push(`<< /Type /Font /Subtype /Type1 /BaseFont /${f} >>`);
  });

  const parts = [Buffer.from("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n", "latin1")];
  const offsets = [0];
  let pos = parts[0].length;
  objs.forEach((o, i) => {
    offsets.push(pos);
    let buf;
    if (typeof o === "string") buf = Buffer.from(`${i + 1} 0 obj\n${o}\nendobj\n`, "latin1");
    else buf = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n${o.dict}\nstream\n`, "latin1"), o.stream, Buffer.from(`\nendstream\nendobj\n`, "latin1")]);
    parts.push(buf);
    pos += buf.length;
  });
  const xrefPos = pos;
  let xref = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objs.length; i++) xref += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  xref += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;
  parts.push(Buffer.from(xref, "latin1"));
  return Buffer.concat(parts);
}

  /* ---- notify newly certified instructors: congrats + portal signup instructions ---- */
  if (path === "notify-certified") {
    const sess = await getSession(req);
    if (!sess || (sess.role !== "instructor" && sess.role !== "admin")) return bad("Sign in required.", 403);
    const list = Array.isArray(body.certs) ? body.certs.filter((c) => c && /@/.test(c.email || "") && c.certId) : [];
    const noShows = Array.isArray(body.noShows) ? body.noShows.filter((n) => n && /@/.test(n.email || "") && n.ref) : [];
    for (const n of noShows) {
      try {
        await sendEmail(n.email, "We missed you — your class credit is saved", `
          <p>Hi ${esc((n.name || "there").split(" ")[0])},</p>
          <p>Our records show you weren't able to attend the <strong>${esc(n.classLabel || "Guardian Shield class")}</strong>${n.classDate ? ` on ${esc(n.classDate)}` : ""}. Life happens — and your seat's value isn't lost.</p>
          <p>Per our policy, registrations are non-refundable, but <strong>your paid registration has been converted to a one-time credit</strong> good for any future class of the same type.</p>
          <p style="background:#242017;border:1px solid #C9A45C;padding:14px 16px;">
            Your credit reference (REF #):<br>
            <span style="font-family:Courier,monospace;font-size:22px;color:#E3CD96;letter-spacing:2px;"><strong>${esc(n.ref)}</strong></span><br>
            <span style="font-size:12px;color:#A99F86;">This is the registration reference from your original confirmation email.</span>
          </p>
          <p><strong>How to use it:</strong></p>
          <ol style="line-height:1.9;">
            <li>Browse upcoming classes at <a href="https://guardianshield.training/?view=training" style="color:#C9A45C;">guardianshield.training</a> and pick a date that works</li>
            <li>Click <strong>Register</strong> and fill in your details</li>
            <li>Enter the REF # above in the <strong>"No-show credit — REF #"</strong> field on the payment step</li>
            <li>Your registration completes immediately — <strong>no new payment required</strong></li>
          </ol>
          <p style="font-size:13px;color:#A99F86;">The credit can be used once. We'll see you on the range.</p>`);
      } catch (e) { console.error("no-show email error:", e); }
    }
    if (!list.length) return json({ ok: true, sent: 0, noShowsNotified: noShows.length });
    let sentCount = 0;
    for (const c of list) {
      const isInstr = c.type !== "standard";
      try {
        let attachments = null;
        try {
          const pdf = buildInstructorCertPdf({ name: c.name || "", certId: c.certId, issued: c.issued || new Date().toISOString().slice(0, 10), expires: c.expires || "", type: isInstr ? "instructor" : "standard" });
          attachments = [{ filename: `Guardian-${isInstr ? "Instructor" : "Graduate"}-Certificate-${c.certId}.pdf`, content: pdf.toString("base64") }];
        } catch (e) { console.error("cert pdf error:", e); }
        if (!isInstr) {
          const result = await sendEmail(c.email, "Congratulations — you're Guardian Shield certified!", `
            <p>Hi ${esc((c.name || "there").split(" ")[0])},</p>
            <p><strong>Congratulations on completing the Guardian Rapid Response Shield certification course!</strong> You trained under live fire, cleared rooms under pressure, and met the Guardian standard. You're now certified to deploy the shield in defense of the people around you.</p>
            <p><strong>Your official Certificate is attached to this email as a PDF</strong>, signed by Aaron K. Gilbert, Program Director. Print it for your records.</p>
            <p style="background:#242017;border:1px solid #C9A45C;padding:14px 16px;">
              Your Certification Number:<br>
              <span style="font-family:Courier,monospace;font-size:22px;color:#E3CD96;letter-spacing:2px;"><strong>${esc(c.certId)}</strong></span><br>
              <span style="font-size:12px;color:#A99F86;">Valid through ${esc(c.expires || "")} · anyone can verify it at guardianshield.training/?view=verify</span>
            </p>
            <p style="font-size:13px;color:#A99F86;">Your certification is valid for 24 months. Keep training — when it's time to recertify, upcoming classes are always at guardianshield.training. Thank you for standing between danger and the people who count on you.</p>`, attachments);
          if (!result.error && !result.skipped) sentCount++;
          continue;
        }
        const result = await sendEmail(c.email, "Congratulations — you're a certified Guardian Shield instructor!", `
          <p>Hi ${esc((c.name || "there").split(" ")[0])},</p>
          <p><strong>Congratulations on becoming a certified Guardian Rapid Response Shield instructor!</strong> You've completed the training and are now authorized to teach this program and certify students of your own.</p>
          <p><strong>Your official Instructor Certificate is attached to this email as a PDF</strong>, signed by Aaron K. Gilbert, Program Director. Print it for your records and keep it with your training credentials.</p>
          <p style="background:#242017;border:1px solid #C9A45C;padding:14px 16px;">
            Your Instructor Certification Number:<br>
            <span style="font-family:Courier,monospace;font-size:22px;color:#E3CD96;letter-spacing:2px;"><strong>${esc(c.certId)}</strong></span><br>
            <span style="font-size:12px;color:#A99F86;">Valid through ${esc(c.expires || "")} · verifiable any time at guardianshield.training/?view=verify</span>
          </p>
          <p><strong>Your next step: create your Instructor Portal account.</strong> The portal is where you'll schedule classes, manage rosters, sign your instructor agreement, and track your commissions.</p>
          <ol style="line-height:1.9;">
            <li>Go to the Instructor Portal using the button below</li>
            <li>Choose <strong>"New instructor? Create an account"</strong></li>
            <li>Sign up with <strong>this email address</strong> and enter your <strong>Instructor Certification Number</strong> above when asked</li>
            <li>Set a password and add the account to an authenticator app (Google Authenticator, Authy, 1Password…)</li>
          </ol>
          <p style="text-align:center;margin:22px 0;">
            <a href="https://guardianshield.training/?view=portal" style="background:#C9A45C;color:#1A1509;font-weight:700;padding:13px 26px;text-decoration:none;letter-spacing:0.04em;">Open the Instructor Portal &rarr;</a>
          </p>
          <p style="font-size:13px;color:#A99F86;">Once you're in, visit the <strong>My Agreement</strong> tab to sign your instructor agreement and submit your W-9 so commission payments can be issued.</p>`, attachments);
        if (!result.error && !result.skipped) sentCount++;
      } catch (e) { console.error("notify-certified error:", e); }
    }
    return json({ ok: true, sent: sentCount, noShowsNotified: noShows.length });
  }

  /* ---- superuser: launch reset — clear all test data atomically ---- */
  if (path === "launch-reset") {
    const sess = await getSession(req);
    if (!isSuper(sess)) return bad("Only the site owner can run the launch reset.", 403);
    const classes = await readJson("gs:classes", []);
    const payments = await readJson("gs:payments", []);
    const certs = await readJson("gs:certs", []);
    const apps = await readJson("gs:apps", []);
    const requests = await readJson("gs:requests", []);
    const notices = await readJson("gs:notices", []);
    const enrollments = classes.reduce((n, c) => n + (c.enrolled || []).length, 0);
    await writeJson("gs:classes", classes.map((c) => ({ ...c, enrolled: [] })));
    await writeJson("gs:payments", []);
    await writeJson("gs:certs", []);
    await writeJson("gs:apps", []);
    await writeJson("gs:requests", []);
    await writeJson("gs:notices", []);
    return json({ ok: true, cleared: { enrollments, payments: payments.length, certs: certs.length, apps: apps.length, requests: requests.length, notices: notices.length } });
  }

  /* ---- admin: invite another administrator ---- */
  if (path === "send-admin-invite") {
    const sess = await getSession(req);
    if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
    const { name, email } = body;
    const inviteRole = body.role === "instructor" ? "instructor" : "admin";
    if (inviteRole === "admin" && !isSuper(sess)) return bad("Only the site owner can add administrators.", 403);
    if (!/@/.test(email || "")) return bad("Enter a valid email address.");
    const accounts = await getAccounts();
    if (findAccount(accounts, email)) return bad("An account with that email already exists.");
    const token = randomToken();
    await writeJson(`gs:admininvite:${token}`, {
      role: inviteRole, name: (name || "").trim(), email: email.trim(),
      invitedBy: sess.email, createdAt: new Date().toISOString(),
      expires: Date.now() + 7 * 24 * 60 * 60 * 1000,
    });
    const inviteUrl = `https://guardianshield.training/?view=${inviteRole === "instructor" ? "portal" : "admin"}&invite=${token}`;
    let emailSent = false;
    if (RESEND_KEY) {
      const subject = inviteRole === "instructor"
        ? "You're invited to join Guardian Shield Training as an instructor"
        : "You're invited to administer Guardian Shield Training";
      const bodyHtml = inviteRole === "instructor" ? `
        <p>Hi ${esc((name || "there").split(" ")[0])},</p>
        <p><strong>${esc(sess.name || sess.email)}</strong> has invited you to join the Guardian Shield Training platform as an instructor.</p>
        <p>Use the button below to create your instructor portal account. You'll set a password and add the account to an authenticator app for two-factor sign-in. Once you're in, you can sign your instructor agreement and submit your W-9 from the My Agreement tab.</p>
        <p style="text-align:center;margin:22px 0;">
          <a href="${inviteUrl}" style="background:#C9A45C;color:#1A1509;font-weight:700;padding:13px 26px;text-decoration:none;letter-spacing:0.04em;">Create your instructor account &rarr;</a>
        </p>
        <p style="font-size:13px;color:#A99F86;">This invitation is for ${esc(email.trim())} only and expires in 7 days. If you weren't expecting it, you can ignore this email.</p>` : `
        <p>Hi ${esc((name || "there").split(" ")[0])},</p>
        <p><strong>${esc(sess.name || sess.email)}</strong> has invited you to become an administrator of the Guardian Shield Training platform.</p>
        <p>Use the button below to create your admin account. You'll set a password and add the account to an authenticator app for two-factor sign-in.</p>
        <p style="text-align:center;margin:22px 0;">
          <a href="${inviteUrl}" style="background:#C9A45C;color:#1A1509;font-weight:700;padding:13px 26px;text-decoration:none;letter-spacing:0.04em;">Create your admin account &rarr;</a>
        </p>
        <p style="font-size:13px;color:#A99F86;">This invitation is for ${esc(email.trim())} only and expires in 7 days. If you weren't expecting it, you can ignore this email.</p>`;
      const result = await sendEmail(email.trim(), subject, bodyHtml);
      emailSent = !result.error && !result.skipped;
    }
    return json({ ok: true, emailSent, inviteUrl });
  }

  /* ---- admin: update an account's details ---- */
  if (path === "admin-update-account") {
    const sess = await getSession(req);
    if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
    const { email, name, company, phone } = body;
    if (!name?.trim()) return bad("Name is required.");
    const accounts = await getAccounts();
    const account = findAccount(accounts, email);
    if (!account) return bad("No account found with that email.", 404);
    account.name = name.trim();
    account.company = (company || "").trim();
    account.phone = (phone || "").trim();
    await saveAccounts(accounts);
    return json({ ok: true, account: publicAccount(account) });
  }

  /* ---- admin: delete an account ---- */
  if (path === "admin-delete-account") {
    const sess = await getSession(req);
    if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
    const { email } = body;
    const accounts = await getAccounts();
    const account = findAccount(accounts, email);
    if (!account) return bad("No account found with that email.", 404);
    if (account.role === "admin" && !isSuper(sess)) return bad("Only the site owner can remove administrators.", 403);
    await saveAccounts(accounts.filter((a) => a !== account));
    return json({ ok: true });
  }

  /* ---- restore session on page load ---- */
  if (path === "me") {
    const sess = await getSession(req);
    if (!sess) return bad("Not signed in.", 401);
    return json({ account: { role: sess.role, name: sess.name, company: sess.company, email: sess.email } });
  }

  if (path === "logout") {
    const sess = await getSession(req);
    if (sess) await store().delete(`sess:${sess.token}`);
    return json({ ok: true });
  }

  return bad("Unknown auth action.", 404);
}

/* ---- protected/public key-value access ---- */
async function handleStorage(req, key, sess) {
  const method = req.method;

  // Public, read-only views
  if (method === "GET" && key === "gs:classes" && !sess) {
    let classes = await readJson("gs:classes", null);
    if (!classes) { classes = SEED_CLASSES; await writeJson("gs:classes", classes); }
    return json({ key, value: JSON.stringify(sanitizeClasses(classes)) });
  }
  if (method === "GET" && key === "gs:media") {
    const v = await store().get(key);
    return json({ key, value: v });
  }
  if (method === "GET" && key === "gs:products" && !sess) {
    const products = await readJson("gs:products", []);
    return json({ key, value: JSON.stringify(products.filter((pr) => pr && pr.active !== false)) });
  }

  // Everything else requires a session
  if (!sess) return bad("Sign in required.", 401);

  // Role rules:
  //  - instructors: full app data (classes, certs, apps, notices, codes, requests, resumes)
  //  - admins: media, plus reporting/user-management data (certs, classes, payments, settings)
  const instructorKeys = /^gs:(classes|certs|apps|notices|codes|requests|resume:.+|doc:.+)$/;
  const adminKeys = /^gs:(media|certs|classes|payments|settings|apps|requests|codes|notices|products|orders|deals|resume:.+|doc:.+)$/;

  const canRead = sess.role === "instructor"
    ? key === "gs:media" || key === "gs:deals" || instructorKeys.test(key)
    : adminKeys.test(key);
  const canWrite = sess.role === "instructor"
    ? instructorKeys.test(key)
    : adminKeys.test(key);

  if (method === "GET") {
    if (!canRead) return bad("Access denied for this key.", 403);
    const v = await store().get(key);
    return json({ key, value: v });
  }

  if (method === "PUT" || method === "POST") {
    if (!canWrite) return bad("Access denied for this key.", 403);
    const bodyText = await req.text();
    if (bodyText.length > 4.5 * 1024 * 1024) return bad("Value too large.", 413);
    await store().set(key, bodyText);
    return json({ ok: true });
  }

  return bad("Method not allowed.", 405);
}

/* ---- public actions, validated server-side ---- */
async function handleRegister(body) {
  const { classId, student, discountCode, passcode } = body;
  const v = await validateRegistration({ classId, student, discountCode, passcode });
  if (v.error) return bad(v.error);
  const done = await finalizeRegistration({
    classId, student, discountCode: v.appliedCode, passcode,
    paidAmount: v.paid, paymentRef: "",
  });
  if (done.error) return bad(done.error);
  return json({ ok: true, ref: done.ref, paid: v.paid });
}

/* ---- Stripe: create a hosted checkout session ---- */
async function handleStoreCheckout(req, body) {
  const { items, customer } = body;
  if (!customer?.name?.trim() || !/@/.test(customer?.email || "")) return bad("Your name and a valid email are required.");
  if (!Array.isArray(items) || items.length === 0) return bad("Your cart is empty.");
  if (items.length > 30) return bad("Too many items in one order.");
  const products = await readJson("gs:products", []);
  const line = [];
  for (const it of items) {
    const prod = products.find((x) => x && x.id === it.id && x.active !== false);
    if (!prod) return bad("An item in your cart is no longer available. Refresh the store and try again.");
    const qty = Math.max(1, Math.min(99, Math.round(Number(it.qty) || 1)));
    line.push({ id: prod.id, name: String(prod.name || "Item").slice(0, 120), price: Math.round((Number(prod.price) || 0) * 100) / 100, qty });
  }
  const total = Math.round(line.reduce((n, l) => n + l.price * l.qty, 0) * 100) / 100;
  if (total <= 0) return bad("Order total must be greater than zero.");

  /* optional discount code — store-scoped codes only */
  let appliedCode = "", coupon = null;
  if (body.discountCode) {
    const codes = await readJson("gs:codes", []);
    const t = String(body.discountCode).trim().toUpperCase();
    const k = codes.find((c) => c.code.toUpperCase() === t);
    const expired = k?.expires && new Date(k.expires + "T23:59:59") < new Date();
    const usedUp = k?.maxUses && (k.uses || 0) >= Number(k.maxUses);
    const scope = k ? (k.scope || "classes") : "classes";
    if (k && k.active && !expired && !usedUp && scope !== "classes") {
      const discount = k.kind === "percent"
        ? Math.round(total * Math.min(Number(k.value), 100)) / 100
        : Math.min(Number(k.value), total);
      if (total - discount <= 0) return bad("That code makes the order free — contact us and we'll arrange your order directly.");
      appliedCode = k.code.toUpperCase();
      coupon = k.kind === "percent"
        ? { "percent_off": Math.min(Number(k.value), 100) }
        : { "amount_off": Math.round(Math.min(Number(k.value), total) * 100), "currency": "usd" };
    } else if (body.discountCode) {
      return bad("That discount code can't be applied to this order.");
    }
  }

  if (!STRIPE_SECRET) return json({ demo: true });

  const origin = new URL(req.url).origin;
  const params = {
    mode: "payment",
    customer_email: customer.email.trim(),
    "shipping_address_collection[allowed_countries][0]": "US",
    success_url: `${origin}/?store=success&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${origin}/?store=cancel`,
  };
  line.forEach((l, i) => {
    params[`line_items[${i}][quantity]`] = l.qty;
    params[`line_items[${i}][price_data][currency]`] = "usd";
    params[`line_items[${i}][price_data][unit_amount]`] = Math.round(l.price * 100);
    params[`line_items[${i}][price_data][product_data][name]`] = l.name;
  });
  if (coupon) {
    const c = await stripeReq("coupons", { duration: "once", ...coupon });
    params["discounts[0][coupon]"] = c.id;
  }
  const session = await stripeReq("checkout/sessions", params);
  await writeJson(`gs:pendorder:${session.id}`, {
    items: line, discountCode: appliedCode,
    customer: { name: customer.name.trim(), email: customer.email.trim(), phone: String(customer.phone || "").trim() },
    expires: Date.now() + 4 * 3600 * 1000,
  });
  return json({ url: session.url });
}

async function handleRegisterWithCredit(body) {
  const { classId, ref, student } = body;
  if (!student?.name?.trim() || !/@/.test(student?.email || "")) return bad("Name and a valid email are required.");
  if (String(student?.phone || "").replace(/\D/g, "").length < 10) return bad("A mobile phone number is required.");
  const refNo = String(ref || "").trim().toUpperCase();
  if (!refNo) return bad("Enter your registration REF # from your original confirmation email.");

  const classes = await readJson("gs:classes", []);
  const target = classes.find((c) => c.id === classId);
  if (!target || target.completed || target.cancelled) return bad("That class is not open for registration.");
  if ((target.enrolled || []).length >= target.seats) return bad("That class is full.");

  let orig = null, origClass = null;
  for (const c of classes) {
    const hit = (c.enrolled || []).find((e) => (e.ref || "").toUpperCase() === refNo);
    if (hit) { orig = hit; origClass = c; break; }
  }
  if (!orig) return bad("That REF # wasn't found. Check your original registration confirmation email.");
  if (!origClass.completed) return bad("That registration is for a class that hasn't taken place yet — no credit is needed.");
  if (!orig.noShow) return bad("That registration was completed — the credit applies only to registrations marked as a no-show.");
  if (orig.creditUsedAt) return bad("That no-show credit has already been used to register for another class.");
  if (!(Number(orig.paid) > 0)) return bad("That registration has no paid amount to credit. Contact us for help.");
  if ((origClass.type || "standard") !== (target.type || "standard")) {
    return bad(`That credit is for the ${origClass.type === "instructor" ? "Instructor Course" : "2-Day Certification"} — it can be applied to a future class of the same type.`);
  }

  orig.creditUsedAt = new Date().toISOString();
  orig.creditToClassId = target.id;
  await writeJson("gs:classes", classes);

  const done = await finalizeRegistration({ classId, student, discountCode: "", passcode: "", paidAmount: 0, paymentRef: "", creditFrom: refNo });
  if (done.error) return bad(done.error);
  return json({ ok: true, free: true, ref: done.ref });
}

async function handleCreateCheckout(req, body) {
  const { classId, student, discountCode, passcode } = body;
  const v = await validateRegistration({ classId, student, discountCode, passcode });
  if (v.error) return bad(v.error);

  // Free after discount — no charge needed, register immediately
  if (v.paid <= 0) {
    const done = await finalizeRegistration({ classId, student, discountCode: v.appliedCode, passcode, paidAmount: 0, paymentRef: "" });
    if (done.error) return bad(done.error);
    return json({ free: true, ref: done.ref });
  }

  // Stripe not configured yet — tell the client to use the demo flow
  if (!STRIPE_SECRET) return json({ demo: true });

  const origin = new URL(req.url).origin;
  const label = `${v.cls.type === "instructor" ? "Instructor Certification Course" : "Guardian 2-Day Certification"} — ${v.cls.date}`;
  const session = await stripeReq("checkout/sessions", {
    mode: "payment",
    customer_email: student.email.trim(),
    "line_items[0][quantity]": 1,
    "line_items[0][price_data][currency]": "usd",
    "line_items[0][price_data][unit_amount]": Math.round(v.paid * 100),
    "line_items[0][price_data][product_data][name]": label,
    success_url: `${origin}/?reg=success&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${origin}/?reg=cancel`,
  });
  await writeJson(`gs:pendreg:${session.id}`, {
    classId, student, discountCode: v.appliedCode, passcode: passcode || "",
    expires: Date.now() + 4 * 3600 * 1000,
  });
  return json({ url: session.url });
}

/* ---- Stripe: webhook records the enrollment after payment ---- */
async function handleStripeWebhook(req) {
  const payload = await req.text();
  if (!STRIPE_WEBHOOK_SECRET) return bad("Webhook secret not configured.", 500);
  const sig = req.headers.get("stripe-signature") || "";
  if (!verifyStripeSignature(payload, sig, STRIPE_WEBHOOK_SECRET)) return bad("Invalid signature.", 400);
  const event = JSON.parse(payload);
  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const pending = await readJson(`gs:pendreg:${session.id}`, null);
    if (pending) {
      await finalizeRegistration({
        classId: pending.classId, student: pending.student,
        discountCode: pending.discountCode, passcode: pending.passcode,
        paidAmount: (session.amount_total ?? 0) / 100,
        paymentRef: session.payment_intent || session.id,
      }).then(async (done) => {
        if (done && done.ref) await writeJson(`gs:doneref:${session.id}`, { ref: done.ref, at: Date.now() });
      });
      await store().delete(`gs:pendreg:${session.id}`);
    }
    const pendOrder = await readJson(`gs:pendorder:${session.id}`, null);
    if (pendOrder) {
      const orders = await readJson("gs:orders", []);
      const ship = session.shipping_details || null;
      const order = {
        id: "ORD-" + uid(), at: new Date().toISOString(),
        customer: pendOrder.customer, items: pendOrder.items,
        total: (session.amount_total ?? 0) / 100,
        paymentRef: session.payment_intent || session.id,
        discountCode: pendOrder.discountCode || "",
        shipping: ship ? { name: ship.name || "", address: ship.address || null } : null,
      };
      orders.unshift(order);
      await writeJson("gs:orders", orders);
      if (pendOrder.discountCode) {
        const codesAll = await readJson("gs:codes", []);
        const kk = codesAll.find((c) => c.code.toUpperCase() === pendOrder.discountCode.toUpperCase());
        if (kk) { kk.uses = (kk.uses || 0) + 1; await writeJson("gs:codes", codesAll); }
      }
      await store().delete(`gs:pendorder:${session.id}`);
      /* order emails — best effort, never block the webhook */
      try {
        const cell = 'padding:6px 8px;border-bottom:1px solid #3A3527;';
        const rows = order.items.map((i) => `<tr><td style="${cell}">${esc(i.name)}</td><td style="${cell}">${i.qty}</td><td style="${cell}">$${(i.price * i.qty).toFixed(2)}</td></tr>`).join("");
        const addr = order.shipping && order.shipping.address ? [order.shipping.name, order.shipping.address.line1, order.shipping.address.line2, `${order.shipping.address.city || ""}, ${order.shipping.address.state || ""} ${order.shipping.address.postal_code || ""}`].filter(Boolean).map(esc).join("<br>") : "";
        await sendEmail(order.customer.email, `Order confirmed — ${order.id}`, `
          <p>Thanks for your order, ${esc((order.customer.name || "there").split(" ")[0])}!</p>
          <p>Your payment was received and your order is confirmed.</p>
          <table width="100%" style="border-collapse:collapse;font-size:13px;color:#EAE3D2;">
            <tr>${["ITEM","QTY","AMOUNT"].map((h) => `<th align="left" style="padding:6px 8px;border-bottom:2px solid #C9A45C;color:#C9A45C;font-size:10px;letter-spacing:1px;">${h}</th>`).join("")}</tr>
            ${rows}
            <tr><td colspan="2" align="right" style="padding:10px 8px;color:#C9A45C;font-size:11px;letter-spacing:1px;">ORDER TOTAL</td><td style="padding:10px 8px;font-size:16px;"><strong>$${order.total.toFixed(2)}</strong></td></tr>
          </table>
          ${addr ? `<p style="font-size:13px;color:#A99F86;">Shipping to:<br>${addr}</p>` : ""}
          <p style="font-size:12px;color:#A99F86;">Order reference: <strong style="color:#C9A45C;">${order.id}</strong> · Keep this email for your records. Questions? Reply to this email.</p>`);
        if (ADMIN_NOTIFY) {
          await sendEmail(ADMIN_NOTIFY, `Store order — ${order.id} — $${order.total.toFixed(2)}`, `
            <p><strong>New store order.</strong></p>
            <p>${esc(order.customer.name)} &lt;${esc(order.customer.email)}&gt;</p>
            <table width="100%" style="border-collapse:collapse;font-size:13px;color:#EAE3D2;">${rows}</table>
            <p>Total: <strong>$${order.total.toFixed(2)}</strong> · Payment: ${esc(order.paymentRef)}</p>
            ${addr ? `<p style="font-size:13px;color:#A99F86;">Ship to:<br>${addr}</p>` : ""}`);
        }
      } catch (e) { console.error("order email error:", e); }
    }
  }
  return json({ received: true });
}

/* ---- Stripe: client polls this after returning from checkout ---- */
async function handleCheckoutStatus(url) {
  const sid = url.searchParams.get("session_id") || "";
  if (!sid) return bad("session_id required.");
  const pending = await readJson(`gs:pendreg:${sid}`, null);
  if (pending) return json({ status: "processing" });
  const classes = await readJson("gs:classes", []);
  for (const c of classes) {
    const hit = (c.enrolled || []).find((e) => e.paymentRef && (e.paymentRef === sid || sid.length > 0 && e.paymentRef && e.registeredAt && false));
    if (hit) return json({ status: "complete", ref: hit.ref });
  }
  // paymentRef stores the payment_intent; also match by session via stored map fallback
  const done = await readJson(`gs:doneref:${sid}`, null);
  if (done) return json({ status: "complete", ref: done.ref });
  return json({ status: "unknown" });
}

async function handleCheckCode(url) {
  const codeQ = String(url.searchParams.get("code") || "").trim().toUpperCase();
  const price = Number(url.searchParams.get("price") || 0);
  const usedFor = url.searchParams.get("for") === "store" ? "store" : "class";
  const codes = await readJson("gs:codes", []);
  const k = codes.find((c) => c.code.toUpperCase() === codeQ);
  if (!k) return bad("That code isn't valid.", 404);
  if (!k.active) return bad("That code is no longer active.", 410);
  if (k.expires && new Date(k.expires + "T23:59:59") < new Date()) return bad("That code has expired.", 410);
  if (k.maxUses && (k.uses || 0) >= Number(k.maxUses)) return bad("That code has reached its usage limit.", 410);
  const scope = k.scope || "classes";
  if (usedFor === "class" && scope === "store") return bad("That code is valid in the store only.", 410);
  if (usedFor === "store" && scope === "classes") return bad("That code is valid for class registrations only.", 410);
  const discount = k.kind === "percent"
    ? Math.round(price * Math.min(Number(k.value), 100)) / 100
    : Math.min(Number(k.value), price);
  return json({ code: k.code.toUpperCase(), kind: k.kind, value: k.value, scope, discount });
}

async function handleCheckPasscode(url) {
  const t = String(url.searchParams.get("code") || "").trim().toUpperCase();
  const apps = await readJson("gs:apps", []);
  const match = apps.find((a) => a.passcode && a.passcode.toUpperCase() === t);
  if (!match || match.status !== "approved") return bad("That passcode isn't valid.", 404);
  if (match.passcodeUsed) return bad("That passcode has already been used.", 410);
  return json({ ok: true });
}

async function handleApply(body) {
  const { name, company, email, phone, background, resumeName, resumeDataUrl } = body;
  if (!name?.trim() || !/@/.test(email || "") || !background?.trim()) return bad("Name, email, and background are required.");
  if (String(phone || "").replace(/\D/g, "").length < 10) return bad("A mobile phone number is required.");
  const id = uid();
  if (resumeDataUrl) {
    if (!resumeDataUrl.startsWith("data:application/pdf")) return bad("Resume must be a PDF.");
    if (resumeDataUrl.length > 5.6 * 1024 * 1024) return bad("Resume must be under 4 MB.");
    await store().set(`gs:resume:${id}`, JSON.stringify(resumeDataUrl));
  }
  const apps = await readJson("gs:apps", []);
  apps.unshift({
    id, name: name.trim(), company: (company || "").trim(), email: email.trim(), phone: (phone || "").trim(),
    background: background.trim(), resumeName: resumeName || "",
    submittedAt: new Date().toISOString(), status: "pending",
  });
  await writeJson("gs:apps", apps);
  if (ADMIN_NOTIFY) {
    try {
      await sendEmail(ADMIN_NOTIFY, "New instructor application", `
        <p><strong>${esc(name)}</strong>${company ? " (" + esc(company) + ")" : ""} applied to become a Guardian Instructor.</p>
        <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">${esc(email)}${phone ? " · " + esc(phone) : ""}<br>${resumeName ? "Resume attached: " + esc(resumeName) : "No resume attached"}</p>
        <p>Review it in the Instructor Portal → Instructor applications.</p>`);
    } catch (e) { console.error("application email error:", e); }
  }
  return json({ ok: true });
}

async function handleRequestClass(body) {
  const { name, email, phone, area, groupSize, timeframe, notes } = body;
  if (!name?.trim() || !/@/.test(email || "") || !area?.trim()) return bad("Name, email, and area are required.");
  const requests = await readJson("gs:requests", []);
  const dupe = requests.find((r) =>
    r.email?.toLowerCase() === email.trim().toLowerCase() &&
    r.area?.toLowerCase() === area.trim().toLowerCase() &&
    Math.abs(new Date() - new Date(r.submittedAt)) < 120000
  );
  if (!dupe) {
    requests.unshift({
      id: uid(), name: name.trim(), email: email.trim(), phone: (phone || "").trim(),
      area: area.trim(), groupSize: groupSize || "", timeframe: (timeframe || "").trim(),
      notes: (notes || "").trim(), submittedAt: new Date().toISOString(), read: false,
    });
    await writeJson("gs:requests", requests);
    if (ADMIN_NOTIFY) {
      try {
        await sendEmail(ADMIN_NOTIFY, "New class request", `
          <p><strong>${esc(name)}</strong> requested a class in <strong>${esc(area)}</strong>.</p>
          <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">${esc(email)}${phone ? " · " + esc(phone) : ""}<br>Group size: ${esc(groupSize || "n/a")} · Timeframe: ${esc(timeframe || "n/a")}${notes ? "<br>Notes: " + esc(notes) : ""}</p>`);
      } catch (e) { console.error("request email error:", e); }
    }
  }
  return json({ ok: true });
}

async function handleVerify(url) {
  const q = String(url.searchParams.get("q") || "").trim().toLowerCase();
  if (!q) return bad("Query required.");
  const certs = await readJson("gs:certs", []);
  const found = certs
    .filter((c) => c.certId.toLowerCase() === q || c.email.toLowerCase() === q)
    .map((c) => ({ certId: c.certId, name: c.name, type: c.type, issued: c.issued, expires: c.expires }));
  return json({ results: found });
}

/* ================= router ================= */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\//, "");
  if (path === "stripe-webhook" && req.method === "POST") {
    try { return await handleStripeWebhook(req); } catch (e) { console.error("webhook error", e); return bad("Webhook error.", 500); }
  }

  let body = {};
  if (["POST", "PUT"].includes(req.method) && !path.startsWith("storage")) {
    try { body = await req.json(); } catch (e) { body = {}; }
  }

  try {
    if (path.startsWith("auth/")) return await handleAuth(req, path.slice(5), body);
    if (path === "storage") {
      const key = url.searchParams.get("key");
      if (!key || !/^gs:[\w:\-\.]+$/.test(key)) return bad("A valid key is required.");
      const sess = await getSession(req);
      return await handleStorage(req, key, sess);
    }
    if (path === "send-approval" && req.method === "POST") {
      const sess = await getSession(url ? req : req);
      if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
      const apps = await readJson("gs:apps", []);
      const app = apps.find((a) => a.id === body.appId);
      if (!app) return bad("Application not found.", 404);
      if (app.status !== "approved" || !app.passcode) return bad("Application is not approved.", 400);
      const result = await sendEmail(app.email, "Your instructor application is approved", `
        <p>Congratulations ${esc(app.name.split(" ")[0])}!</p>
        <p>Your application to become a Guardian Instructor has been <strong style="color:#6FBF8F;">approved</strong>.</p>
        <p>Next step: register for an upcoming <strong>Instructor Certification Course</strong> on the Class Schedule page at guardianshield.training. At registration, enter your personal approval passcode:</p>
        <p style="background:#242017;border:1px solid #C9A45C;padding:14px 16px;text-align:center;font-family:Courier,monospace;font-size:20px;color:#E3CD96;letter-spacing:2px;">${esc(app.passcode)}</p>
        <p>This passcode is valid for one course registration.</p>
        <p style="text-align:center;margin:24px 0 8px;">
          <a href="https://guardianshield.training/?view=schedule"
             style="background:#C9A45C;color:#1A1509;text-decoration:none;font-weight:bold;font-size:15px;padding:13px 28px;border-radius:2px;display:inline-block;">
            View the Class Schedule &rarr;
          </a>
        </p>`);
      if (result.skipped) return json({ ok: true, emailed: false, reason: "Email service not configured." });
      if (result.error) return bad("Email failed to send: " + result.error, 502);
      app.approvalEmailedAt = new Date().toISOString();
      await writeJson("gs:apps", apps);
      return json({ ok: true, emailed: true });
    }
    if (path === "send-statement" && req.method === "POST") {
      const sess = await getSession(req);
      if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
      const payments = await readJson("gs:payments", []);
      const p = payments.find((x) => x.id === body.paymentId);
      if (!p) return bad("Payment not found.", 404);
      if (!p.items || !p.items.length) return bad("This payment has no itemized statement.", 400);
      const isJm4 = p.payeeType === "jm4";
      const accounts = await getAccounts();
      let recipients;
      if (isJm4) {
        recipients = /@/.test(p.recipientEmail || "") ? [p.recipientEmail.trim()] : [];
      } else if ((p.payeeType || "instructor") === "company") {
        recipients = accounts.filter((a) => a.role === "instructor" && (a.company || "").toLowerCase() === p.payee.toLowerCase()).map((a) => a.email);
      } else {
        const a = accounts.find((x) => x.role === "instructor" && x.name.toLowerCase() === p.payee.toLowerCase());
        recipients = a ? [a.email] : [];
      }
      recipients = [...new Set(recipients)];
      if (!recipients.length) return json({ emailed: false, reason: isJm4 ? "No statement email was provided for JM4 Tactical — print the statement and deliver it manually." : "No portal account matches this payee — print the statement and deliver it manually." });

      const cell = 'padding:6px 8px;border-bottom:1px solid #3A3527;';
      const rows = isJm4
        ? p.items.map((i) => `<tr>
        <td style="${cell}">${esc(i.date)}</td><td style="${cell}">${esc(i.certId || i.ref)}</td>
        <td style="${cell}">${esc(i.student)}</td><td style="${cell}">${esc(i.gradType || "—")}</td>
        <td style="${cell}"><strong>$${Number(i.fee ?? i.commission).toFixed(2)}</strong></td>
      </tr>`).join("")
        : p.items.map((i) => `<tr>
        <td style="${cell}">${esc(i.date)}</td><td style="${cell}">${esc(i.classId)}</td>
        <td style="${cell}">${esc(i.student)}</td><td style="${cell}">$${Number(i.paid).toFixed(2)}</td>
        <td style="${cell}">${esc(i.rate)}%</td><td style="${cell}"><strong>$${Number(i.commission).toFixed(2)}</strong></td>
      </tr>`).join("");
      const html = isJm4 ? `
        <p>A Certification Fee payment has been issued to <strong>JM4 Tactical, LLC</strong> by Guardian Shield Training (The Armored Citizen, LLC), as compensation for creation of the program's training content — $50.00 per graduating student and instructor.</p>
        <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">
          Paid to: <strong>${esc(p.payee)}</strong> (Training content licensor)<br>
          Payment date: ${esc(p.date)}<br>
          Check # / EFT record: <strong style="color:#C9A45C;">${esc(p.checkRef || "—")}</strong>${p.note ? `<br>Note: ${esc(p.note)}` : ""}
        </p>
        <table width="100%" style="border-collapse:collapse;font-size:13px;color:#EAE3D2;">
          <tr>
            ${["GRADUATED","CERT ID","GRADUATE","TYPE","CERTIFICATION FEE"].map((h) => `<th align="left" style="padding:6px 8px;border-bottom:2px solid #C9A45C;color:#C9A45C;font-size:10px;letter-spacing:1px;">${h}</th>`).join("")}
          </tr>
          ${rows}
          <tr>
            <td colspan="4" align="right" style="padding:10px 8px;color:#C9A45C;font-size:11px;letter-spacing:1px;">TOTAL PAYMENT — ${p.items.length} CERTIFICATION FEE${p.items.length === 1 ? "" : "S"}</td>
            <td style="padding:10px 8px;font-size:17px;"><strong>$${Number(p.amount).toFixed(2)}</strong></td>
          </tr>
        </table>
        <p>Please keep this statement for your records. Questions about this payment? Reply to this email.</p>` : `
        <p>A commission payment has been issued to you by Guardian Shield Training.</p>
        <p style="background:#242017;border:1px solid #3A3527;padding:12px 16px;">
          Paid to: <strong>${esc(p.payee)}</strong> (${(p.payeeType || "instructor") === "company" ? "Company" : "Instructor"})<br>
          Payment date: ${esc(p.date)}<br>
          Check # / EFT record: <strong style="color:#C9A45C;">${esc(p.checkRef || "—")}</strong>${p.note ? `<br>Note: ${esc(p.note)}` : ""}
        </p>
        <table width="100%" style="border-collapse:collapse;font-size:13px;color:#EAE3D2;">
          <tr>
            ${["CLASS DATE","CLASS","STUDENT","STUDENT PAID","RATE","COMMISSION"].map((h) => `<th align="left" style="padding:6px 8px;border-bottom:2px solid #C9A45C;color:#C9A45C;font-size:10px;letter-spacing:1px;">${h}</th>`).join("")}
          </tr>
          ${rows}
          <tr>
            <td colspan="5" align="right" style="padding:10px 8px;color:#C9A45C;font-size:11px;letter-spacing:1px;">TOTAL PAYMENT — ${p.items.length} STUDENT COMMISSION${p.items.length === 1 ? "" : "S"}</td>
            <td style="padding:10px 8px;font-size:17px;"><strong>$${Number(p.amount).toFixed(2)}</strong></td>
          </tr>
        </table>
        <p>Please keep this statement for your records. Questions about this payment? Reply to this email.</p>`;
      const result = await sendEmail(recipients, isJm4 ? `Certification fee payment issued — $${Number(p.amount).toFixed(2)}` : `Commission payment issued — $${Number(p.amount).toFixed(2)}`, html);
      if (result.skipped) return json({ emailed: false, reason: "Email service not configured." });
      if (result.error) return bad("Email failed: " + result.error, 502);
      p.statementEmailedAt = new Date().toISOString();
      p.statementEmailedTo = recipients.join(", ");
      await writeJson("gs:payments", payments);
      return json({ emailed: true, to: recipients });
    }
    if (path === "agreement-status") {
      const sess = await getSession(req);
      if (!sess || sess.role !== "instructor") return bad("Instructor sign-in required.", 403);
      const rec = await readJson(`gs:agreement:${sess.email.toLowerCase()}`, null);
      const w9 = await readJson(`gs:w9:${sess.email.toLowerCase()}`, null);
      return json({
        signedAt: rec ? rec.signedAt : null,
        w9UploadedAt: w9 ? w9.uploadedAt : null, w9Name: w9 ? w9.fileName : "",
        docs: { version: AGREEMENT_VERSION, agreement: INSTRUCTOR_AGREEMENT },
      });
    }

    if (path === "sign-agreement" && req.method === "POST") {
      const sess = await getSession(req);
      if (!sess || sess.role !== "instructor") return bad("Instructor sign-in required.", 403);
      const { typedName } = body;
      if (!typedName || typedName.trim().length < 3) return bad("Please type your full legal name as your signature.");
      const key = `gs:agreement:${sess.email.toLowerCase()}`;
      const existing = await readJson(key, null);
      if (existing) return json({ ok: true, alreadySigned: true, signedAt: existing.signedAt });
      const signedAt = new Date().toISOString();
      const accounts = await getAccounts();
      const account = findAccount(accounts, sess.email);
      const record = {
        instructorName: account ? account.name : sess.name, instructorEmail: sess.email,
        company: account ? account.company || "" : "",
        typedSignature: typedName.trim(), signedAt, docVersion: AGREEMENT_VERSION,
        ip: req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for") || "",
        userAgent: req.headers.get("user-agent") || "",
        agreement: INSTRUCTOR_AGREEMENT,
      };
      await writeJson(key, record);
      if (account) { account.agreementSignedAt = signedAt; await saveAccounts(accounts); }
      try {
        const agrHtml = INSTRUCTOR_AGREEMENT.map(([h, t]) => `<p style="margin:8px 0;"><strong>${esc(h)}.</strong> ${esc(t)}</p>`).join("");
        await sendEmail(sess.email, "Your signed Instructor Agreement", `
          <p>Hi ${esc((account ? account.name : sess.name).split(" ")[0])},</p>
          <p>This is your copy of the Instructor Agreement you signed with The Armored Citizen, LLC dba Guardian Shield Training. Keep it for your records.</p>
          ${agrHtml}
          <p style="background:#242017;border:1px solid #C9A45C;padding:12px 16px;margin-top:18px;">
            <strong>Electronically signed by:</strong> ${esc(record.typedSignature)}<br>
            Date &amp; time: ${new Date(signedAt).toLocaleString("en-US", { timeZone: "America/Denver" })} (Mountain)<br>
            Document version: ${AGREEMENT_VERSION}
          </p>
          <p>Reminder: please also upload your completed IRS Form W-9 in the Instructor Portal if you haven't yet — it's required before commission payments can be issued.</p>`);
        if (ADMIN_NOTIFY) await sendEmail(ADMIN_NOTIFY, "Instructor Agreement signed", `
          <p><strong>${esc(record.instructorName)}</strong>${record.company ? " (" + esc(record.company) + ")" : ""} signed the Instructor Agreement (v${AGREEMENT_VERSION}).</p>
          <p>View it in the Admin Portal → Users → Instructors.</p>`);
      } catch (e) { console.error("agreement email error:", e); }
      return json({ ok: true, signedAt });
    }

    if (path === "upload-w9" && req.method === "POST") {
      const sess = await getSession(req);
      if (!sess || sess.role !== "instructor") return bad("Instructor sign-in required.", 403);
      const { fileName, dataUrl } = body;
      if (!fileName || !dataUrl || !dataUrl.startsWith("data:application/pdf;base64,")) return bad("Please upload your completed W-9 as a PDF file.");
      if (dataUrl.length > 5.6 * 1024 * 1024) return bad("That file is too large — please keep the W-9 under 4 MB.");
      const uploadedAt = new Date().toISOString();
      await writeJson(`gs:w9:${sess.email.toLowerCase()}`, { fileName: fileName.slice(0, 120), dataUrl, uploadedAt, instructorEmail: sess.email });
      const accounts = await getAccounts();
      const account = findAccount(accounts, sess.email);
      if (account) { account.w9UploadedAt = uploadedAt; account.w9Name = fileName.slice(0, 120); await saveAccounts(accounts); }
      if (ADMIN_NOTIFY) {
        try {
          await sendEmail(ADMIN_NOTIFY, "W-9 uploaded", `
            <p><strong>${esc(account ? account.name : sess.email)}</strong> uploaded a completed W-9 (${esc(fileName)}).</p>
            <p>For security, the form itself is not attached — view or download it in the Admin Portal → Users → Instructors.</p>`);
        } catch (e) { console.error("w9 email error:", e); }
      }
      return json({ ok: true, uploadedAt });
    }

    if (path === "agreement") {
      const sess = await getSession(req);
      if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
      const rec = await readJson(`gs:agreement:${(url.searchParams.get("email") || "").toLowerCase()}`, null);
      if (!rec) return bad("No signed agreement found.", 404);
      return json(rec);
    }

    if (path === "w9") {
      const sess = await getSession(req);
      if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
      const rec = await readJson(`gs:w9:${(url.searchParams.get("email") || "").toLowerCase()}`, null);
      if (!rec) return bad("No W-9 on file.", 404);
      return json(rec);
    }

    if (path === "sign-info") {
      const token = url.searchParams.get("token") || "";
      if (token.length < 10) return bad("Invalid signing link.", 400);
      const classes = await readJson("gs:classes", []);
      for (const c of classes) {
        const st = (c.enrolled || []).find((e) => e.signToken === token);
        if (st) {
          return json({
            student: { name: st.name, email: st.email, ref: st.ref },
            cls: { date: c.date, time: c.time, location: c.location, city: c.city || "", state: c.state || "", instructor: c.instructor, type: c.type },
            docs: { version: DOC_VERSION, briefing: RANGE_BRIEFING, waiver: LIABILITY_WAIVER },
            signedAt: st.waiverSignedAt || null,
          });
        }
      }
      return bad("This signing link is not valid or the registration was cancelled.", 404);
    }

    if (path === "sign" && req.method === "POST") {
      const { token, typedName } = body;
      if (!token || token.length < 10) return bad("Invalid signing link.", 400);
      if (!typedName || typedName.trim().length < 3) return bad("Please type your full legal name as your signature.");
      const classes = await readJson("gs:classes", []);
      for (const c of classes) {
        const st = (c.enrolled || []).find((e) => e.signToken === token);
        if (!st) continue;
        if (st.waiverSignedAt) return json({ ok: true, alreadySigned: true, signedAt: st.waiverSignedAt });
        const signedAt = new Date().toISOString();
        const record = {
          token, classId: c.id, ref: st.ref,
          studentName: st.name, studentEmail: st.email,
          typedSignature: typedName.trim(), signedAt,
          docVersion: DOC_VERSION,
          ip: req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for") || "",
          userAgent: req.headers.get("user-agent") || "",
          briefing: RANGE_BRIEFING, waiver: LIABILITY_WAIVER,
        };
        await writeJson(`gs:waiver:${token}`, record);
        st.waiverSignedAt = signedAt;
        await writeJson("gs:classes", classes);

        const notices = await readJson("gs:notices", []);
        const place = [c.location, [c.city, c.state].filter(Boolean).join(", ")].filter(Boolean).join(" — ");
        notices.unshift({ id: uid(), when: new Date().toLocaleString("en-US", { timeZone: "America/Denver" }), classId: c.id, read: false,
          text: `Forms signed — ${st.name} electronically signed the Range Safety Briefing and Liability Waiver for the ${c.date} class at ${place}.` });
        await writeJson("gs:notices", notices);

        try {
          const docsHtml = (title, sections) => `<h3 style="color:#C9A45C;font-size:15px;margin:18px 0 6px;">${title}</h3>` +
            sections.map(([h, t]) => `<p style="margin:8px 0;"><strong>${esc(h)}.</strong> ${esc(t)}</p>`).join("");
          await sendEmail(st.email, "Your signed training forms", `
            <p>Hi ${esc(st.name.split(" ")[0])},</p>
            <p>This is your copy of the forms you electronically signed for your class on <strong>${esc(c.date)}</strong> at ${esc(place)}. Keep it for your records.</p>
            ${docsHtml("Range Safety Briefing", RANGE_BRIEFING)}
            ${docsHtml("Release and Waiver of Liability", LIABILITY_WAIVER)}
            <p style="background:#242017;border:1px solid #C9A45C;padding:12px 16px;margin-top:18px;">
              <strong>Electronically signed by:</strong> ${esc(record.typedSignature)}<br>
              Date &amp; time: ${new Date(signedAt).toLocaleString("en-US", { timeZone: "America/Denver" })} (Mountain)<br>
              Registration: ${st.ref} · Document version: ${DOC_VERSION}
            </p>`);
        } catch (e) { console.error("signed-copy email error:", e); }

        return json({ ok: true, signedAt });
      }
      return bad("This signing link is not valid or the registration was cancelled.", 404);
    }

    if (path === "waiver") {
      const sess = await getSession(req);
      if (!sess) return bad("Sign in required.", 403);
      const token = url.searchParams.get("token") || "";
      const record = await readJson(`gs:waiver:${token}`, null);
      if (!record) return bad("No signed form found.", 404);
      return json(record);
    }

    if (path === "run-reminders" && req.method === "POST") {
      const sess = await getSession(req);
      if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
      return json(await runReminders());
    }
    if (path === "email-status") {
      return json({
        phase3Deployed: true,
        resendKeyPresent: !!RESEND_KEY,
        resendKeyLooksValid: RESEND_KEY.startsWith("re_"),
        adminNotifySet: !!ADMIN_NOTIFY,
        emailFrom: EMAIL_FROM,
        stripeKeyPresent: !!STRIPE_SECRET,
        stripeMode: STRIPE_SECRET.startsWith("sk_test_") ? "test" : STRIPE_SECRET.startsWith("sk_live_") ? "live" : "none",
        demoMode: DEMO_MODE,
      });
    }
    if (path === "register" && req.method === "POST") return await handleRegister(body);
    if (path === "create-checkout" && req.method === "POST") return await handleCreateCheckout(req, body);
    if (path === "register-with-credit" && req.method === "POST") return await handleRegisterWithCredit(body);
    if (path === "store-checkout" && req.method === "POST") return await handleStoreCheckout(req, body);
    if (path === "checkout-status") return await handleCheckoutStatus(url);
    if (path === "check-code") return await handleCheckCode(url);
    if (path === "check-passcode") return await handleCheckPasscode(url);
    if (path === "apply" && req.method === "POST") return await handleApply(body);
    if (path === "request-class" && req.method === "POST") return await handleRequestClass(body);
    if (path === "verify") return await handleVerify(url);
    return bad("Not found.", 404);
  } catch (e) {
    console.error("API error:", e);
    return bad("Server error.", 500);
  }
};

export const config = { path: "/api/*" };
