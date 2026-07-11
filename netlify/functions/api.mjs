// Guardian Shield Training — server API (Phase 1: server-side authentication)
// Handles: auth (signup/login/2FA/sessions), protected data access, and
// server-validated public actions (registration, applications, class requests,
// certificate verification). Data lives in Netlify Blobs.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

/* ================= configuration =================
   Set these in Netlify: Site configuration → Environment variables
   INSTRUCTOR_ENROLL_KEY  (default "SHIELD")
   ADMIN_ENROLL_KEY       (default "ADMIN")
   DEMO_MODE              set to "false" to stop returning demo 2FA codes */
const INSTRUCTOR_KEY = (process.env.INSTRUCTOR_ENROLL_KEY || "SHIELD").toUpperCase();
const ADMIN_KEY = (process.env.ADMIN_ENROLL_KEY || "ADMIN").toUpperCase();
const DEMO_MODE = process.env.DEMO_MODE !== "false";
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

/* ================= route handlers ================= */
async function handleAuth(req, path, body) {
  /* ---- signup: validate, stage pending, return TOTP secret ---- */
  if (path === "signup") {
    const { role, name, company, email, phone, password, enrollKey } = body;
    if (!["instructor", "admin"].includes(role)) return bad("Invalid role.");
    if (!name?.trim()) return bad("Enter your name.");
    if (!/@/.test(email || "")) return bad("Enter a valid email address.");
    if ((password || "").length < 8) return bad("Password must be at least 8 characters.");
    const wanted = role === "admin" ? ADMIN_KEY : INSTRUCTOR_KEY;
    if (String(enrollKey || "").trim().toUpperCase() !== wanted) return bad("Invalid enrollment key.");
    const accounts = await getAccounts();
    if (findAccount(accounts, email)) return bad("An account with that email already exists.");
    const salt = newSalt();
    const pendingToken = randomToken();
    const pending = {
      type: "signup", expires: Date.now() + 15 * 60 * 1000,
      account: {
        id: uid(), role, name: name.trim(), company: (company || "").trim(),
        email: email.trim(), phone: (phone || "").trim(),
        salt, hash: hashPassword(password, salt),
        totpSecret: makeTotpSecret(), twofa: "totp",
        created: new Date().toISOString().slice(0, 10),
      },
      smsCode: sixDigits(),
    };
    await writeJson(`auth:pending:${pendingToken}`, pending);
    return json({
      pendingToken,
      totpSecret: pending.account.totpSecret,
      ...(DEMO_MODE ? { demoSms: pending.smsCode } : {}),
    });
  }

  /* ---- finish signup after 2FA proof ---- */
  if (path === "verify-setup") {
    const { pendingToken, code, method } = body;
    const pending = await readJson(`auth:pending:${pendingToken}`, null);
    if (!pending || pending.type !== "signup" || pending.expires < Date.now()) return bad("Setup expired — start again.", 410);
    const ok = method === "sms"
      ? safeEqual(String(code).trim(), pending.smsCode)
      : verifyTotp(pending.account.totpSecret, code);
    if (!ok) return bad("That code didn't match. Try again.", 401);
    const account = { ...pending.account, twofa: method === "sms" ? "sms" : "totp" };
    const accounts = await getAccounts();
    if (findAccount(accounts, account.email)) return bad("An account with that email already exists.");
    await saveAccounts([...accounts, account]);
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
    const smsCode = sixDigits();
    await writeJson(`auth:pending:${pendingToken}`, {
      type: "login", email: account.email, smsCode, expires: Date.now() + 10 * 60 * 1000,
    });
    return json({
      pendingToken, twofa: account.twofa,
      ...(DEMO_MODE ? { demoSms: smsCode, demoTotpSecret: account.totpSecret } : {}),
    });
  }

  /* ---- login step 2: 2FA ---- */
  if (path === "verify-login") {
    const { pendingToken, code, method } = body;
    const pending = await readJson(`auth:pending:${pendingToken}`, null);
    if (!pending || pending.type !== "login" || pending.expires < Date.now()) return bad("Sign-in expired — start again.", 410);
    const accounts = await getAccounts();
    const account = findAccount(accounts, pending.email);
    if (!account) return bad("Account not found.", 401);
    const ok = method === "sms"
      ? safeEqual(String(code).trim(), pending.smsCode)
      : verifyTotp(account.totpSecret, code);
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
    const smsCode = sixDigits();
    await writeJson(`auth:pending:${pendingToken}`, {
      type: "reset", email: account.email, smsCode, expires: Date.now() + 10 * 60 * 1000,
    });
    return json({
      pendingToken, twofa: account.twofa,
      ...(DEMO_MODE ? { demoSms: smsCode, demoTotpSecret: account.totpSecret } : {}),
    });
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
    const ok = method === "sms"
      ? safeEqual(String(code).trim(), pending.smsCode)
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
    return json({ accounts: accounts.map((a) => ({ ...publicAccount(a), twofa: a.twofa, created: a.created })) });
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
  const adminReadable = ["gs:media", "gs:certs", "gs:classes", "gs:payments", "gs:settings"];
  const adminWritable = ["gs:media", "gs:certs", "gs:classes", "gs:payments", "gs:settings"];

  const canRead = sess.role === "instructor"
    ? key === "gs:media" || instructorKeys.test(key)
    : adminReadable.includes(key);
  const canWrite = sess.role === "instructor"
    ? instructorKeys.test(key)
    : adminWritable.includes(key);

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
  if (!student?.name?.trim() || !/@/.test(student?.email || "")) return bad("Name and a valid email are required.");
  const classes = await readJson("gs:classes", []);
  const cls = classes.find((c) => c.id === classId);
  if (!cls || cls.completed || cls.cancelled) return bad("That class is not open for registration.");
  if ((cls.enrolled || []).length >= cls.seats) return bad("That class is full.");

  // Instructor course passcode check
  if (cls.type === "instructor") {
    const apps = await readJson("gs:apps", []);
    const t = String(passcode || "").trim().toUpperCase();
    const match = apps.find((a) => a.passcode && a.passcode.toUpperCase() === t);
    if (!match || match.status !== "approved") return bad("A valid instructor approval passcode is required.");
    if (match.passcodeUsed) return bad("That passcode has already been used.");
    match.passcodeUsed = true;
    match.passcodeUsedAt = new Date().toISOString();
    await writeJson("gs:apps", apps);
  }

  // Discount code
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
      k.uses = (k.uses || 0) + 1;
      await writeJson("gs:codes", codes);
    }
  }

  const record = {
    name: student.name.trim(), email: student.email.trim(), phone: (student.phone || "").trim(),
    company: (student.company || "").trim(),
    ref: "REG-" + uid(), registeredAt: new Date().toISOString(),
    discountCode: appliedCode, paid,
  };
  cls.enrolled = [...(cls.enrolled || []), record];
  await writeJson("gs:classes", classes);

  const notices = await readJson("gs:notices", []);
  const place = [cls.location, [cls.city, cls.state].filter(Boolean).join(", ")].filter(Boolean).join(" — ");
  notices.unshift({
    id: uid(), when: new Date().toLocaleString(), classId: cls.id, read: false,
    text: `New registration — ${record.name} (${record.email}) enrolled in ${cls.type === "instructor" ? "Instructor Course" : "2-Day Certification"} on ${cls.date} at ${place}. Paid $${paid.toFixed(2)}${appliedCode ? ` (code ${appliedCode})` : ""}.`,
  });
  await writeJson("gs:notices", notices);
  return json({ ok: true, ref: record.ref, paid });
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
    if (path === "register" && req.method === "POST") return await handleRegister(body);
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
