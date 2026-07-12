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
async function sendEmail(to, subject, bodyHtml) {
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
      body: JSON.stringify({ from: EMAIL_FROM, to: Array.isArray(to) ? to : [to], subject, html }),
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
async function finalizeRegistration({ classId, student, discountCode, passcode, paidAmount, paymentRef }) {
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
  };
  cls.enrolled = [...(cls.enrolled || []), record];
  await writeJson("gs:classes", classes);

  const notices = await readJson("gs:notices", []);
  const place = [cls.location, [cls.city, cls.state].filter(Boolean).join(", ")].filter(Boolean).join(" — ");
  notices.unshift({
    id: uid(), when: new Date().toLocaleString(), classId: cls.id, read: false,
    text: `New registration — ${record.name} (${record.email}) enrolled in the ${cls.type === "instructor" ? "Instructor Course" : "2-Day Certification"} scheduled for ${cls.date} at ${place}. Paid $${paidAmount.toFixed(2)}${discountCode ? ` (code ${discountCode})` : ""}${paymentRef ? " via Stripe" : ""}.`,
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
        Amount paid: $${paidAmount.toFixed(2)}${discountCode ? ` (code ${esc(discountCode)})` : ""}<br>
        Registration reference: <strong style="color:#C9A45C;">${record.ref}</strong>
      </p>
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
    if (k && k.active && !expired && !usedUp) {
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
    } else {
      const wanted = role === "admin" ? ADMIN_KEY : INSTRUCTOR_KEY;
      if (String(enrollKey || "").trim().toUpperCase() !== wanted) return bad("Invalid enrollment key.");
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

  /* ---- admin: invite another administrator ---- */
  if (path === "send-admin-invite") {
    const sess = await getSession(req);
    if (!sess || sess.role !== "admin") return bad("Admin access required.", 403);
    const { name, email } = body;
    const inviteRole = body.role === "instructor" ? "instructor" : "admin";
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

  // Everything else requires a session
  if (!sess) return bad("Sign in required.", 401);

  // Role rules:
  //  - instructors: full app data (classes, certs, apps, notices, codes, requests, resumes)
  //  - admins: media, plus reporting/user-management data (certs, classes, payments, settings)
  const instructorKeys = /^gs:(classes|certs|apps|notices|codes|requests|resume:.+)$/;
  const adminKeys = /^gs:(media|certs|classes|payments|settings|apps|requests|codes|notices|resume:.+)$/;

  const canRead = sess.role === "instructor"
    ? key === "gs:media" || instructorKeys.test(key)
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
  const codes = await readJson("gs:codes", []);
  const k = codes.find((c) => c.code.toUpperCase() === codeQ);
  if (!k) return bad("That code isn't valid.", 404);
  if (!k.active) return bad("That code is no longer active.", 410);
  if (k.expires && new Date(k.expires + "T23:59:59") < new Date()) return bad("That code has expired.", 410);
  if (k.maxUses && (k.uses || 0) >= Number(k.maxUses)) return bad("That code has reached its usage limit.", 410);
  const discount = k.kind === "percent"
    ? Math.round(price * Math.min(Number(k.value), 100)) / 100
    : Math.min(Number(k.value), price);
  return json({ code: k.code.toUpperCase(), kind: k.kind, value: k.value, discount });
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
      const accounts = await getAccounts();
      let recipients;
      if ((p.payeeType || "instructor") === "company") {
        recipients = accounts.filter((a) => a.role === "instructor" && (a.company || "").toLowerCase() === p.payee.toLowerCase()).map((a) => a.email);
      } else {
        const a = accounts.find((x) => x.role === "instructor" && x.name.toLowerCase() === p.payee.toLowerCase());
        recipients = a ? [a.email] : [];
      }
      recipients = [...new Set(recipients)];
      if (!recipients.length) return json({ emailed: false, reason: "No portal account matches this payee — print the statement and deliver it manually." });

      const cell = 'padding:6px 8px;border-bottom:1px solid #3A3527;';
      const rows = p.items.map((i) => `<tr>
        <td style="${cell}">${esc(i.date)}</td><td style="${cell}">${esc(i.classId)}</td>
        <td style="${cell}">${esc(i.student)}</td><td style="${cell}">$${Number(i.paid).toFixed(2)}</td>
        <td style="${cell}">${esc(i.rate)}%</td><td style="${cell}"><strong>$${Number(i.commission).toFixed(2)}</strong></td>
      </tr>`).join("");
      const html = `
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
      const result = await sendEmail(recipients, `Commission payment issued — $${Number(p.amount).toFixed(2)}`, html);
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
