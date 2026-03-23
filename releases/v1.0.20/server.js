// NAF Events – server.js
// Version: 1.0.1
const express  = require("express");
const session  = require("express-session");
const bcrypt   = require("bcrypt");
const multer   = require("multer");
const fs       = require("fs");
const path     = require("path");
const { v4: uuid } = require("uuid");

// ── E-post via Nodemailer + Runbox SMTP ──────────────────────────
// Konfigurasjon via miljøvariabler (settes i docker-compose.yml / Portainer):
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
//   TEST_EMAIL_OVERRIDE  – send all mail to this address instead (testing)
let _transporter = null;
function getTransporter() {
  if (_transporter) return _transporter;
  try {
    const nodemailer = require("nodemailer");
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || "587");
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    if (!host || !user || !pass) return null;
    _transporter = nodemailer.createTransport({
      host, port,
      secure: port === 465,
      auth: { user, pass },
      tls: { rejectUnauthorized: false },
    });
    return _transporter;
  } catch(e) {
    console.error("[email] nodemailer not available:", e.message);
    return null;
  }
}

async function sendEmail({ to, subject, html, text, replyTo }) {
  const s = getSettings();
  if (!s.emailEnabled) {
    console.log("[email] Disabled in settings – skipping to:", to);
    writeEmailLog({ status: "skipped", to, subject, reason: "email_disabled" });
    return { ok: false, reason: "email_disabled" };
  }
  const transport = getTransporter();
  if (!transport) {
    console.error("[email] No transporter – check SMTP_HOST/USER/PASS env vars");
    writeEmailLog({ status: "error", to, subject, reason: "smtp_not_configured" });
    return { ok: false, reason: "smtp_not_configured" };
  }
  const fromAddr = process.env.SMTP_FROM || s.emailFrom || ("noreply@" + (s.eventDomain || DOMAIN));
  const fromName = s.emailFromName || "Events Admin";
  const from = `${fromName} <${fromAddr}>`;

  // Test override: redirect all mail to a single address
  const testOverride = process.env.TEST_EMAIL_OVERRIDE;
  let actualTo = to;
  let actualSubject = subject;
  if (testOverride) {
    actualTo = testOverride;
    actualSubject = `[TEST → ${to}] ${subject}`;
  }

  try {
    const info = await transport.sendMail({
      from, to: actualTo, subject: actualSubject,
      html, text,
      ...(replyTo ? { replyTo } : {}),
    });
    console.log("[email] Sendt til:", actualTo, "| MsgID:", info.messageId);
    return { ok: true, id: info.messageId };
  } catch(e) {
    console.error("[email] Feil:", e.message);
    return { ok: false, reason: e.message };
  }
}

// ── E-postmaler ──────────────────────────────────────────────────
// Konverter ren tekst til HTML for e-post
function _textToEmailHtml(text, siteName, settings) {
  const accent   = (settings.colors && settings.colors.accent) || "#FFD100";
  const logoUrl  = settings.logoUrl || "";
  const logoHtml = logoUrl
    ? `<img src="${logoUrl}" style="height:28px;object-fit:contain;vertical-align:middle" alt="${escHtml(siteName)}"/>`
    : `<span style="font-weight:900">${escHtml(siteName)}</span>`;

  const bodyHtml = escHtml(text)
    .split("\n\n").join('</p><p style="margin:0 0 1em;color:#333;font-size:.95rem;line-height:1.7">')
    .split("\n").join("<br>");

  return `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
  <div style="background:${accent};padding:1.25rem 1.5rem;border-radius:8px 8px 0 0">${logoHtml}</div>
  <div style="background:#f9f9f9;padding:2rem;border-radius:0 0 8px 8px;border:1px solid #e0e0e0">
    <p style="margin:0 0 1em;color:#333;font-size:.95rem;line-height:1.7">${bodyHtml}</p>
    <hr style="border:none;border-top:1px solid #e0e0e0;margin:1.5rem 0">
    <p style="font-size:.75rem;color:#999;margin:0">🔒 Vi lagrer kun navn og e-post for å administrere påmeldingen. Data anonymiseres automatisk etter arrangementet.</p>
  </div>
</div>`;
}

// Erstattt malvariabler med faktiske verdier
function applyEmailVars(text, ev, reg, settings) {
  if (!text) return text;
  const siteName = settings.siteName || "Events Admin";
  const contact  = settings.contactEmail || "";
  const dateStr  = ev.date ? new Date(ev.date).toLocaleDateString("nb-NO", {weekday:"long",year:"numeric",month:"long",day:"numeric"}) : "";
  const timeStr  = ev.date ? new Date(ev.date).toLocaleTimeString("nb-NO", {hour:"2-digit",minute:"2-digit"}) : "";
  const firstName = (reg.name || "").split(" ")[0];
  const evUrl    = "https://" + ev.slug + "." + (settings.eventDomain || "naf-events.no");
  const regs     = ev.registrations || [];
  const cancelUrl = reg.cancelUrl || (reg.cancelToken
    ? "https://" + ev.slug + "." + (settings.eventDomain || "naf-events.no") + "/avmeld?token=" + reg.cancelToken
    : "");

  const vars = {
    "{{navn}}":           reg.name  || "",
    "{{fornavn}}":        firstName || "",
    "{{event_tittel}}":  ev.title  || "",
    "{{dato}}":           dateStr,
    "{{tid}}":            timeStr,
    "{{sted}}":           ev.location || "",
    "{{pin}}":            reg.checkinPin || "",
    "{{avmeld_lenke}}":  cancelUrl,
    "{{kontakt_email}}": contact,
    "{{org_navn}}":      siteName,
    "{{event_url}}":     evUrl,
    "{{max_deltakere}}": String(ev.maxParticipants || ""),
    "{{antall_pameldt}}":String(regs.filter(function(r){return !r.anonymized;}).length),
    "{{premie}}":         (ev.lottery && ev.lottery.prize) || "",
    "{{epost}}":          reg.email || "",
    "{{passord}}":        reg.tempPassword || "",
    "{{login_url}}":     "https://" + (settings.adminDomain || ("admin." + (settings.eventDomain || "naf-events.no"))),
  };

  // Betingede blokker {{#var}}innhold{{/var}}
  text = text.replace(/\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\}\}/g, function(m, key, inner) {
    const v = vars["{{" + key + "}}"];
    return (v && v.length) ? inner : "";
  });

  // Enkle variabler
  Object.entries(vars).forEach(function(kv) {
    text = text.split(kv[0]).join(kv[1]);
  });
  return text;
}

function emailRegConfirmation(ev, reg, settings) {
  const siteName   = settings.siteName || "Events Admin";
  const contact    = settings.contactEmail || "";
  const dateStr    = ev.date ? new Date(ev.date).toLocaleDateString("nb-NO", { weekday:"long", year:"numeric", month:"long", day:"numeric" }) : "";
  const timeStr    = ev.date ? new Date(ev.date).toLocaleTimeString("nb-NO", { hour:"2-digit", minute:"2-digit" }) : "";

  // Bruk egendefinert mal hvis den finnes
  const tplType = (ev.eventType === "stand") ? "interest" : "registration";
  const customTpls = ev._resolvedEmailTemplates || settings.emailTemplates || {};
  const tpl = customTpls[tplType] || customTpls["registration"];
  if (tpl && tpl.subject && tpl.body) {
    const cancelUrl = reg.cancelToken
      ? "https://" + ev.slug + "." + (settings.eventDomain || "naf-events.no") + "/avmeld?token=" + reg.cancelToken
      : "";
    const regWithCancel = Object.assign({}, reg, { cancelUrl });
    const subject = applyEmailVars(tpl.subject, ev, regWithCancel, settings);
    const bodyText = applyEmailVars(tpl.body, ev, regWithCancel, settings);
    const html = _textToEmailHtml(bodyText, siteName, settings);
    const text = bodyText;
    return { subject, html, text };
  }

  const checkinPinLine = reg.checkinPin ? `<p><strong>Din innsjekk-PIN: ${reg.checkinPin}</strong> – oppgi denne på tableten ved ankomst.</p>` : "";
  const subject    = `✅ Påmelding bekreftet – ${ev.title}`;
  const html = `
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
  <div style="background:#FFD100;padding:1.5rem 2rem;border-radius:8px 8px 0 0">
    <h1 style="margin:0;font-size:1.3rem;color:#1a1a1a">${siteName}</h1>
  </div>
  <div style="background:#f9f9f9;padding:2rem;border-radius:0 0 8px 8px;border:1px solid #e0e0e0">
    <h2 style="margin-top:0">Hei ${reg.name}!</h2>
    <p>Du er nå påmeldt:</p>
    <div style="background:#fff;border-left:4px solid #FFD100;padding:1rem 1.25rem;border-radius:4px;margin:1rem 0">
      <strong style="font-size:1.1rem">${ev.title}</strong><br>
      ${dateStr ? `<span style="color:#555">📅 ${dateStr}${timeStr ? " kl. " + timeStr : ""}</span><br>` : ""}
      ${ev.location ? `<span style="color:#555">📍 ${ev.location}</span>` : ""}
    </div>
    ${checkinPinLine}
    <p style="color:#555;font-size:.9rem">
      Har du spørsmål? ${contact ? `Ta kontakt på <a href="mailto:${contact}">${contact}</a>.` : "Ta kontakt med arrangøren."}
    </p>
    ${reg.cancelUrl ? `<p style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e0e0e0;font-size:.8rem;color:#999">Vil du avmelde deg? <a href="${reg.cancelUrl}" style="color:#888">Klikk her for å avmelde deg</a></p>` : ""}
    <hr style="border:none;border-top:1px solid #e0e0e0;margin:1.5rem 0">
    <p style="font-size:.75rem;color:#999;margin:0">
      🔒 Vi lagrer kun navn, e-post og telefon for å administrere påmeldingen. 
      Data deles ikke med tredjeparter og anonymiseres automatisk etter arrangementet.
    </p>
  </div>
</div>`;
  const text = `Hei ${reg.name}!\n\nDu er påmeldt: ${ev.title}\n${dateStr ? dateStr + (timeStr ? " kl. " + timeStr : "") + "\n" : ""}${ev.location ? ev.location + "\n" : ""}\n${contact ? "Spørsmål? " + contact : ""}\n\n– ${siteName}`;
  return { subject, html, text };
}

function emailTurFinalized(ev, reg, settings) {
  const siteName  = settings.siteName || "Events Admin";
  const contact   = settings.contactEmail || "";
  const dateStr   = ev.date ? new Date(ev.date).toLocaleDateString("nb-NO", { weekday:"long", year:"numeric", month:"long", day:"numeric" }) : "";
  const timeStr   = ev.date ? new Date(ev.date).toLocaleTimeString("nb-NO", { hour:"2-digit", minute:"2-digit" }) : "";
  const endDateStr = ev.endDate ? new Date(ev.endDate).toLocaleDateString("nb-NO", { weekday:"long", year:"numeric", month:"long", day:"numeric" }) : "";
  const firstName = (reg.name || "").split(" ")[0];
  const route     = ev.route || {};
  const days      = route.days || [];
  const etappeHtml = days.length ? days.map(function(day, di) {
    const etapper = (day.etapper || []).filter(function(e){ return e.fra || e.til; });
    if (!etapper.length) return "";
    const dayLabel = day.dato
      ? new Date(day.dato).toLocaleDateString("nb-NO", { weekday:"long", day:"numeric", month:"long" })
      : ("Dag " + (di + 1));
    const rows = etapper.map(function(e) {
      const opplevelseIcons = { museum:"🏛️", natur:"🌿", utsikt:"🏔️", historisk:"🏰", aktivitet:"🎭", kultur:"🎨", mat:"🍴", annet:"⭐" };
      const typeIcon = e.type === "opplevelse"
        ? (opplevelseIcons[e.opplevelseSubtype] || "⭐")
        : { start:"🏁", stopp:"📍", lunsj:"🍽️", middag:"🍷", hotell:"🏨", slutt:"🏁", bensin:"⛽" }[e.type] || "📍";
      const km = e.km ? " · " + e.km + " km" : "";
      const notat = e.notat ? "<br><span style='color:#888;font-size:.85rem'>" + escHtml(e.notat) + "</span>" : "";
      return "<tr><td style=\"padding:.4rem .6rem;border-bottom:1px solid #eee;white-space:nowrap\">" + typeIcon + " " + escHtml(e.fra || "") + "</td>"
           + "<td style=\"padding:.4rem .6rem;border-bottom:1px solid #eee\">→ " + escHtml(e.til || "") + km + notat + "</td></tr>";
    }).join("");
    return "<h3 style=\"font-size:1rem;font-weight:700;color:#1a1a1a;margin:1.25rem 0 .5rem\">" + escHtml(dayLabel) + "</h3>"
         + "<table style=\"width:100%;border-collapse:collapse;font-size:.9rem\">" + rows + "</table>";
  }).join("") : "";
  const hotelLine = reg.hotelRoom
    ? "<p><strong>Hotellrom:</strong> " + (reg.hotelRoom === "enkel" ? "Enkeltrom 🛏" : "Dobbeltrom 🛏🛏") + "</p>"
    : "";
  const subject = "🗺️ Turplan klar – " + escHtml(ev.title);
  const html = "<div style=\"font-family:sans-serif;max-width:600px;margin:0 auto;color:#1a1a1a\">"
    + "<div style=\"background:#FFD100;padding:1.5rem 2rem;border-radius:8px 8px 0 0\"><h1 style=\"margin:0;font-size:1.3rem;color:#1a1a1a\">" + escHtml(siteName) + "</h1></div>"
    + "<div style=\"background:#f9f9f9;padding:2rem;border-radius:0 0 8px 8px;border:1px solid #e0e0e0\">"
    + "<h2 style=\"margin-top:0\">Hei " + escHtml(firstName) + "! Turen er klar 🎉</h2>"
    + "<p>Vi er klare for <strong>" + escHtml(ev.title) + "</strong> og her er alle detaljene du trenger.</p>"
    + "<div style=\"background:#fff;border-left:4px solid #FFD100;padding:1rem 1.25rem;border-radius:4px;margin:1rem 0\">"
    + (ev.date ? "<p style=\"margin:.2rem 0\"><strong>📅 Avreise:</strong> " + escHtml(dateStr) + (timeStr ? " kl. " + timeStr : "") + "</p>" : "")
    + (endDateStr ? "<p style=\"margin:.2rem 0\"><strong>🏁 Hjemkomst:</strong> " + escHtml(endDateStr) + "</p>" : "")
    + (ev.location ? "<p style=\"margin:.2rem 0\"><strong>📍 Oppmøtested:</strong> " + escHtml(ev.location) + "</p>" : "")
    + hotelLine + "</div>"
    + (etappeHtml ? "<h2 style=\"font-size:1.1rem;font-weight:700;margin:1.5rem 0 .25rem\">🗺️ Reiserute</h2>" + etappeHtml : "")
    + (ev.description ? "<h2 style=\"font-size:1.1rem;font-weight:700;margin:1.5rem 0 .25rem\">ℹ️ Om turen</h2><p style=\"line-height:1.7;color:#333\">" + escHtml(ev.description).replace(/\n/g,"<br>") + "</p>" : "")
    + "<hr style=\"border:none;border-top:1px solid #e0e0e0;margin:1.5rem 0\">"
    + (contact ? "<p style=\"font-size:.85rem;color:#555\">Spørsmål? Kontakt oss på <a href=\"mailto:" + escHtml(contact) + "\" style=\"color:#1a1a1a\">" + escHtml(contact) + "</a></p>" : "")
    + "<p style=\"font-size:.75rem;color:#999;margin:0\">🔒 Personopplysninger brukes kun til å administrere turen og slettes automatisk etterpå.</p>"
    + "</div></div>";
  const text = "Hei " + reg.name + "!\n\nTuren er klar: " + ev.title + "\n"
    + (dateStr ? dateStr + (timeStr ? " kl. " + timeStr : "") + "\n" : "")
    + (ev.location ? "Oppmøtested: " + ev.location + "\n" : "")
    + (reg.hotelRoom ? "Hotellrom: " + reg.hotelRoom + "\n" : "")
    + "\n" + (contact ? "Spørsmål? " + contact : "") + "\n\n– " + siteName;
  return { subject, html, text };
}

function emailCancellationConfirmation(ev, reg, settings) {
  const siteName = settings.siteName || "Events Admin";

  // Bruk egendefinert mal hvis den finnes
  const customTpls = ev._resolvedEmailTemplates || settings.emailTemplates || {};
  const tpl = customTpls["cancellation"];
  if (tpl && tpl.subject && tpl.body) {
    const subject = applyEmailVars(tpl.subject, ev, reg, settings);
    const bodyText = applyEmailVars(tpl.body, ev, reg, settings);
    return { subject, html: _textToEmailHtml(bodyText, siteName, settings), text: bodyText };
  }

  const subject  = `Avmelding bekreftet – ${ev.title}`;
  const html = `
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
  <div style="background:#FFD100;padding:1.5rem 2rem;border-radius:8px 8px 0 0">
    <h1 style="margin:0;font-size:1.3rem;color:#1a1a1a">${siteName}</h1>
  </div>
  <div style="background:#f9f9f9;padding:2rem;border-radius:0 0 8px 8px;border:1px solid #e0e0e0">
    <h2 style="margin-top:0">Hei ${reg.name}!</h2>
    <p>Vi bekrefter at du er avmeldt fra <strong>${ev.title}</strong>.</p>
    <p style="color:#555;font-size:.9rem">Ønsker du å melde deg på igjen kan du gjøre det via arrangementssiden.</p>
  </div>
</div>`;
  const text = `Hei ${reg.name}!\n\nDu er avmeldt fra: ${ev.title}\n\n– ${siteName}`;
  return { subject, html, text };
}

const APP_VERSION = "1.0.0"; // Oppdateres automatisk ved installasjon via update/apply

const app          = express();
const DATA         = process.env.DATA_DIR     || "./data";
const DOMAIN       = process.env.BASE_DOMAIN  || "naf-events.no";
const ADMIN_DOMAIN = process.env.ADMIN_DOMAIN || ("admin." + DOMAIN);
const SECRET       = process.env.SESSION_SECRET || "change-me-in-env";
if (!process.env.SESSION_SECRET) console.warn("[SIKKERHET] SESSION_SECRET er ikke satt! Sett den i Portainer miljøvariabler.");
const GH_KEY       = process.env.GRAPHHOPPER_KEY || "";

const USERS_FILE    = path.join(DATA, "users.json");
const EVENTS_FILE   = path.join(DATA, "events.json");
const SETTINGS_FILE = path.join(DATA, "settings.json");
const MEMBERS_FILE  = path.join(DATA, "members.json");
const WISHES_F   = path.join(DATA, "wishes.json");
const UPLOADS    = path.join(DATA, "uploads");
const DEVLOG_OWNER = process.env.DEVLOG_OWNER || ("admin@" + (process.env.BASE_DOMAIN || "events-admin.no"));

// ── Breakglass accounts ──────────────────────────────────────────
// Provisioned via env vars only – never via UI
// BREAKGLASS_1=email:password  BREAKGLASS_2=email:password  BREAKGLASS_3=email:password
const BREAKGLASS_LOG_FILE = path.join(DATA, "breakglass_log.json");
function getBreakglassAccounts() {
  const accounts = [];
  [process.env.BREAKGLASS_1, process.env.BREAKGLASS_2, process.env.BREAKGLASS_3]
    .forEach(function(val, i) {
      if (!val) return;
      const sep = val.indexOf(":");
      if (sep < 1) return;
      accounts.push({ index: i + 1, email: val.slice(0, sep).toLowerCase().trim(), password: val.slice(sep + 1) });
    });
  return accounts;
}
function isBreakglassEmail(email) {
  return getBreakglassAccounts().some(function(a) { return a.email === email.toLowerCase(); });
}

const DEVLOG_F     = path.join(DATA, "devlog.json");
const SERIES_F     = path.join(DATA, "series.json");
const BLOCKS_F     = path.join(DATA, "blocks.json");
const VOLUNTEERS_FILE = path.join(DATA, "volunteers.json");
const INVENTAR_FILE   = path.join(DATA, "inventar.json");
const EMAIL_LOG_FILE  = path.join(DATA, "email_log.json");

// ── SSE (Server-Sent Events) ─────────────────────────────────────
// Klienter abonnerer på /api/events/stream?department=xxx
const sseClients = new Map(); // clientId → { res, department }
let sseNextId = 1;

function broadcastEventUpdate(department) {
  sseClients.forEach(function(client) {
    // null department = global change (t.ex. avdelning opprettet/slettet) → send til alle
    // ellers: send til klienter uten filter, eller med matchende filter
    if (department === null || !client.department || client.department === department) {
      try {
        client.res.write("data: " + JSON.stringify({ type: "events_updated", department }) + "\n\n");
      } catch(e) { /* klient koblet fra */ }
    }
  });
}

fs.mkdirSync(UPLOADS, { recursive: true });
fs.mkdirSync(DATA,    { recursive: true });

// Auto-create data files if missing
[
  [USERS_FILE,     "[]"],
  [EVENTS_FILE,    "[]"],
  [MEMBERS_FILE,   "[]"],
  [VOLUNTEERS_FILE,"[]"],
  [INVENTAR_FILE,  "[]"],
  [BLOCKS_F,       "[]"],
  [SERIES_F,       "[]"],
  [WISHES_F,       "[]"],
  [DEVLOG_F,       '{"entries":[]}'],
  [SETTINGS_FILE,  JSON.stringify({ eventDomain: DOMAIN, siteName: "Events Admin", contactEmail: "", departments: [], setupDone: false })],
  [EMAIL_LOG_FILE,      "[]"],
  [BREAKGLASS_LOG_FILE, "[]"],
].forEach(function([f, init]) {
  if (!fs.existsSync(f)) fs.writeFileSync(f, init);
});

// ── Storage helpers ──────────────────────────────────────────────
const readJSON  = function(f) { try { return JSON.parse(fs.readFileSync(f)); } catch(e) { return []; } };
// Atomar skriving: skriv til .tmp, rename – unngår korrupt JSON ved krasj
const writeJSON = function(f, d) {
  const tmp = f + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(d, null, 2));
  fs.renameSync(tmp, f);
};

// ── XSS-beskyttelse ───────────────────────────────────────────────
function escHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// ── Settings ─────────────────────────────────────────────────────
const defaultSettings = {
  eventDomain: DOMAIN,
  siteName: "Events Admin",
  contactEmail: "",
  showCountdown: true,
  showParticipantCount: true,
  allowSelfCheckIn: true,
  requireGuestbookApproval: true,
  departments: [],
  setupDone: false,
  logoUrl: "",
  theme: "dark",
  typeNames: {
    kurs:  "Kurs",
    tur:   "Tur",
    stand: "Stand",
    mote:  "Møte",
  },
  colors: {
    accent: "#FFD100",
    card: "#2A2A2A",
    kursBg: "#1a3a5a", kursBorder: "#2a5a8a",
    turBg: "#3a1a5a",  turBorder: "#5a2a8a",
    standBg: "#1a3a1a", standBorder: "#2a5a2a",
    anyBg: "#3a3a1a",  anyBorder: "#5a5a2a",
  },
};

const getSettings = function() {
  try { return Object.assign({}, defaultSettings, JSON.parse(fs.readFileSync(SETTINGS_FILE))); }
  catch(e) { return Object.assign({}, defaultSettings); }
};
const saveSettings = function(s) { writeJSON(SETTINGS_FILE, s); };

// ── Typenavn-hjelper ────────────────────────────────────────────────
function getTypeLabel(eventType, settings) {
  const tn = (settings && settings.typeNames) || {};
  if (eventType === "kurs")  return tn.kurs  || "Kurs";
  if (eventType === "tur")   return tn.tur   || "Tur";
  if (eventType === "mote")  return tn.mote  || "Møte";
  if (eventType === "stand") return tn.stand || "Stand";
  return tn.stand || "Stand";
}

// ── E-postlogg ───────────────────────────────────────────────────
const EMAIL_LOG_MAX = 500;
function writeEmailLog(entry) {
  try {
    const log = readJSON(EMAIL_LOG_FILE);
    log.unshift(Object.assign({ id: require("crypto").randomBytes(6).toString("hex"), ts: new Date().toISOString() }, entry));
    if (log.length > EMAIL_LOG_MAX) log.length = EMAIL_LOG_MAX;
    writeJSON(EMAIL_LOG_FILE, log);
  } catch(e) {
    console.error("[emaillog] Kunne ikke skrive logg:", e.message);
  }
}

// ── One-time migration: add department:null to inventar items without it ──
(function migrateInventar() {
  try {
    const items = readJSON(INVENTAR_FILE);
    let changed = false;
    items.forEach(function(item) {
      if (!Object.prototype.hasOwnProperty.call(item, "department")) {
        item.department = null;
        changed = true;
      }
    });
    if (changed) {
      writeJSON(INVENTAR_FILE, items);
      console.log("[migration] Added department:null to", items.length, "inventar items");
    }
  } catch(e) { console.error("[migration] inventar:", e.message); }
})();

// ── Init default admin ───────────────────────────────────────────
(async function() {
  if (!fs.existsSync(USERS_FILE) || readJSON(USERS_FILE).length === 0) {
    const hash = await bcrypt.hash("admin123", 12);
    const adminEmail = "admin@" + DOMAIN;
    writeJSON(USERS_FILE, [{
      id: uuid(), email: adminEmail,
      hash: hash, role: "admin", name: "Admin", department: null
    }]);
    console.log("Default admin: " + adminEmail + " / admin123");
  }
})();

// ── Middleware ───────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

// Grunnleggende security headers (uten helmet-avhengighet)
app.use(function(req, res, next) {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "DENY");
  res.set("X-XSS-Protection", "1; mode=block");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://unpkg.com; " +
    "style-src 'self' 'unsafe-inline' https://unpkg.com; " +
    "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://*.openstreetmap.org; " +
    "frame-src https://www.openstreetmap.org; " +
    "connect-src 'self' " +
      "https://photon.komoot.io " +
      "https://nominatim.openstreetmap.org " +
      "https://overpass-api.de " +
      "https://router.project-osrm.org " +
      "https://graphhopper.com " +
      "https://brouter.de " +
      "https://cdnjs.cloudflare.com " +
      "https://unpkg.com; " +
    "font-src 'self'; " +
    "frame-ancestors 'none';"
  );
  next();
});

// Ingen caching på API-svar (viktig bak Traefik)
app.use("/api", function(req, res, next) {
  res.set("Cache-Control", "no-store");
  next();
});
app.use("/uploads", express.static(UPLOADS));
// Prevent Cloudflare cdn-cgi script injection errors
app.get("/cdn-cgi/*", function(req, res) { res.status(204).end(); });
app.use("/static", express.static(path.join(__dirname, "static")));
app.use(session({
  name: "naf_sid",
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production" ? "auto" : false,
    sameSite: "lax",
    maxAge: 86400000 * 7,
    httpOnly: true,
  }
}));

// Filtype-validering for opplastinger
const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const upload = multer({
  dest: UPLOADS,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: function(req, file, cb) {
    if (ALLOWED_IMAGE_TYPES.indexOf(file.mimetype) === -1) {
      return cb(new Error("Kun bilder er tillatt (jpeg, png, gif, webp)"));
    }
    cb(null, true);
  }
});

// ── Subdomain → event page (MÅ ligge FØR express.static) ────────
app.use(function(req, res, next) {
  if (req.path.startsWith("/api") || req.path.startsWith("/uploads") || req.path.startsWith("/avmeld") || req.path.startsWith("/static") || req.path.startsWith("/gb-photo") || req.path.startsWith("/gb-photos") || req.path.startsWith("/logo")) return next();

  const host = (req.headers["x-forwarded-host"] || req.hostname || "").split(",")[0].trim().toLowerCase();

  // Reserverte subdomener som ikke skal behandles som event-slug
  const RESERVED = ["sso", "www", "mail", "smtp", "ftp", "api"];
  if (host === ADMIN_DOMAIN || host === DOMAIN || host === "www." + DOMAIN) return next();
  const sub0 = host.split(".")[0];
  if (RESERVED.indexOf(sub0) !== -1) return next();

  var slug = null;
  var domains = [DOMAIN];
  try {
    var s = getSettings();
    if (s.eventDomain && domains.indexOf(s.eventDomain) === -1) domains.push(s.eventDomain);
  } catch(e) {}

  for (var i = 0; i < domains.length; i++) {
    var d = domains[i];
    if (host === d || host === "www." + d) break;
    var sub = host.replace("." + d, "");
    if (sub && sub !== host && sub !== "www") { slug = sub; break; }
  }

  if (slug) {
    // Check if slug matches a department
    var settings = getSettings();
    var dept = (settings.departments || []).find(function(a) { return a.slug === slug; });
    if (dept) return serveDepartmentPage(dept, req, res);
    req.eventSlug = slug;
    return serveEventPage(req, res);
  }
  next();
});

// Service Worker må serveres fra rot med no-cache
app.get("/sw.js", function(req, res) {
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Content-Type", "application/javascript");
  const domain = DOMAIN;
  res.send(`
const SW_VERSION = "events-admin-v6";
const EVENT_CACHE = SW_VERSION + "-events";

// Install – skip waiting immediately, no precaching
self.addEventListener("install", function(e) {
  e.waitUntil(self.skipWaiting());
});

// Activate – delete ALL old caches, claim all clients
self.addEventListener("activate", function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(keys.map(function(k) { return caches.delete(k); }));
    }).then(function() {
      return self.clients.claim();
    }).then(function() {
      // Tell all clients to reload so they pick up the clean state
      return self.clients.matchAll({ type: "window" }).then(function(clients) {
        clients.forEach(function(c) { c.postMessage({ type: "SW_UPDATED" }); });
      });
    })
  );
});

// Fetch – ONLY intercept public event subdomain pages, never admin
self.addEventListener("fetch", function(e) {
  const url = new URL(e.request.url);
  // Pass through everything on the admin domain untouched
  if (url.hostname === "${ADMIN_DOMAIN || 'admin.' + domain}") return;
  // Only cache GET requests for public event pages and snapshots
  if (e.request.method !== "GET") return;
  const isEventPage = url.hostname.endsWith(".${domain}") && url.pathname === "/";
  const isSnapshot  = url.pathname.match(/^\\/api\\/events\\/[^/]+\\/snapshot$/);
  if (isEventPage || isSnapshot) {
    e.respondWith(
      fetch(e.request).then(function(res) {
        var clone = res.clone();
        caches.open(EVENT_CACHE).then(function(c) { c.put(e.request, clone); });
        return res;
      }).catch(function() {
        return caches.match(e.request);
      })
    );
  }
  // All other requests: don't intercept, let browser handle normally
});

// Message from page: precache upcoming event URLs
self.addEventListener("message", function(e) {
  if (e.data && e.data.type === "PRECACHE_EVENTS") {
    var urls = e.data.urls || [];
    caches.open(EVENT_CACHE).then(function(cache) {
      urls.forEach(function(url) {
        fetch(url).then(function(res) {
          if (res.ok) cache.put(url, res);
        }).catch(function() {});
      });
    });
  }
});
`);
});


// Static files (index.html, app.js, sw.js etc.)
app.use(express.static(__dirname));

// ── Auth guards ──────────────────────────────────────────────────
const auth = function(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Ikke innlogget" });
  // Breakglass sessions are not in users.json – skip DB refresh
  if (req.session.user.role === "breakglass") return next();
  // Synkroniser alltid accessList fra fil – fanger opp endringer etter login
  var fresh = readJSON(USERS_FILE).find(function(u){ return u.id === req.session.user.id; });
  if (fresh) {
    req.session.user.role      = fresh.role;
    req.session.user.accessList = getAccessList(fresh);
    req.session.user.name      = fresh.name;
    req.session.user.title     = fresh.tittel || null;
  }
  next();
};
const adminOnly = function(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") return next();
  res.status(403).json({ error: "Kun for administratorer" });
};
const managerOrAdmin = function(req, res, next) {
  if (!req.session.user) return res.status(403).json({ error: "Ikke innlogget" });
  var u = req.session.user;
  // Admin alltid OK
  if (u.role === "admin") return next();
  // Other roles OK if they have at least one access entry
  if (getAccessList(u).length > 0) return next();
  res.status(403).json({ error: "Ingen tilgang" });
};


// Gets the user's access list. New model: accessList[] array per department.
// Legacy fallback: use department field for old users with empty accessList[].
function getAccessList(user) {
  if (Array.isArray(user.accessList) && user.accessList.length) return user.accessList;
  if (user.department) return [{ department: user.department, subgroups: user.subgroups || [], eventTyper: user.eventTyper || [], role: (user.role === "department_manager" || user.role === "avdelingsleder") ? "department_manager" : "event_manager" }];
  return [];
}





const canEditEvent = function(ev, user) {
  if (!user) return false;
  if (user.role === "admin") return true;
  var accessList = getAccessList(user);

  for (var i = 0; i < accessList.length; i++) {
    var t = accessList[i];
    var roleVal = t.role || "arrangementsansvarlig";

    // Department manager: can edit all events in their department,
    // AND events with no department assigned (unowned events)
    if (roleVal === "department_manager" || roleVal === "avdelingsleder") {
      if (!ev.department || t.department === ev.department) return true;
      continue;
    }

    // For subgroup/event managers: department must match (or event has no dept)
    if (ev.department && t.department !== ev.department) continue;

    if (roleVal === "subgroup_manager" || roleVal === "undergruppeansvarlig") {
      // Can edit events in their own subgroups
      if (ev.subgroup && t.subgroups && t.subgroups.indexOf(ev.subgroup) !== -1) return true;
      // Can edit events with no subgroup only if they created it
      if (!ev.subgroup && ev.createdBy && ev.createdBy === user.email) return true;
      continue;
    }

    if (roleVal === "event_manager" || roleVal === "arrangementsansvarlig") {
      // Must have created the event
      if (ev.createdBy && ev.createdBy !== user.email) continue;
      var evType = ev.eventType || "stand";
      if (t.eventTyper && t.eventTyper.length && t.eventTyper.indexOf(evType) === -1) continue;
      if (ev.subgroup && t.subgroups && t.subgroups.length && t.subgroups.indexOf(ev.subgroup) === -1) continue;
      return true;
    }
  }

  // Last resort: user created the event themselves
  if (ev.createdBy && ev.createdBy === user.email) return true;

  return false;
};

// ── Permissions ──────────────────────────────────────────────────
// Calculate what the user is allowed to do – frontend bruker kun disse flaggene,
// aldri role direkte. All tilgangskontroll skjer fortsatt i server.
// Breakglass: minimal permission set – restore + reset admin password only
function buildBreakglassPermissions() {
  return {
    isBreakglass:       true,
    isAdmin:            false,
    isManager:          false,
    isSubgroupManager:  false,
    isEventManager:     false,
    canCreateEvent:     false,
    canManageUsers:     false,
    canManageDepartments: false,
    canSeeMembers:      false,
    canRunGdpr:         false,
    canEditBlocks:      false,
    canBreakglassRestore: true,
    canBreakglassResetAdmin: true,
    editableDepartments: [],
    mySubgroups: [],
    accessList: [],
  };
}

function buildPermissions(user, settings) {
  var departments = settings.departments || [];
  var accessList  = getAccessList(user);
  var isAdmin  = user.role === "admin";

  // Hent rettigheter fra org-rolle-systemet
  var rp = getRolePermissions(user);

  // Bakoverkompatibilitet: map gamle roller
  var isManager = isAdmin ||
    (user.role === "department_manager" || user.role === "avdelingsleder") ||
    accessList.some(function(t) { return t.role === "department_manager" || t.role === "avdelingsleder"; }) ||
    rp.manageDepartments || rp.manageSubgroups;

  var isSubgroupManager = (user.role === "undergruppeansvarlig") ||
    accessList.some(function(t) { return t.role === "subgroup_manager" || t.role === "undergruppeansvarlig"; }) ||
    (rp.manageSubgroups && !isManager);

  var isEventManager = (user.role === "arrangementsansvarlig") ||
    accessList.some(function(t) { return t.role === "event_manager" || t.role === "arrangementsansvarlig"; }) ||
    rp.createEvent;

  var canCreateSomething = isManager || isSubgroupManager || isEventManager || rp.createEvent;

  var myDepartment = accessList.length ? accessList[0].department : (user.department || null);
  var myDeptObj   = departments.find(function(a) { return a.id === myDepartment; }) || null;
  var myDepartmentName  = myDeptObj ? myDeptObj.name : null;

  var editableDepartments = isAdmin
    ? departments.map(function(a) { return { id: a.id, name: a.name, subgroups: a.subgroups || [] }; })
    : accessList.map(function(t) {
        var dept = departments.find(function(a) { return a.id === t.department; });
        return dept ? { id: dept.id, name: dept.name, subgroups: dept.subgroups || [], myRole: t.role, mySubgroups: t.subgroups || [], myEventTypes: t.eventTypes || [] } : null;
      }).filter(Boolean);

  var mySubgroupsList = [];
  accessList.forEach(function(t) {
    if (!t.subgroups || !t.subgroups.length) return;
    var deptObj = departments.find(function(a) { return a.id === t.department; });
    if (!deptObj) return;
    (deptObj.subgroups || []).forEach(function(u) {
      if (t.subgroups.indexOf(u.id) !== -1 && !mySubgroupsList.find(function(x){ return x.id === u.id; }))
        mySubgroupsList.push(u);
    });
  });

  return {
    canSeeDevlog:   user.email === DEVLOG_OWNER,

    // Org
    canManageDepartments:   isAdmin || rp.manageDepartments,
    canManageSubgroups:     isAdmin || isManager || rp.manageSubgroups,

    // Events
    canCreateEvent:         canCreateSomething,
    canSetDepartment:       isAdmin,
    canSetDepartmentField:  isAdmin,

    // Brukere
    canManageUsers:         isAdmin || isManager || isSubgroupManager || rp.manageUsers,
    canCreateUsersForDept:  isAdmin || isManager || rp.manageUsers,
    canCreateUsersForSubgroup: (isSubgroupManager && !isManager) || rp.manageUsers,

    // Medlemmer
    canSeeMembers:          isAdmin || isManager || isSubgroupManager || rp.manageMembers,
    canImportMembers:       isAdmin || isManager || isSubgroupManager || rp.manageMembers,
    canDeleteMembers:       isAdmin || isManager || rp.manageMembers,

    // Inventar
    canSeeInventar:         isAdmin || isManager || rp.manageInventar,
    canEditInventar:        isAdmin || isManager || rp.manageInventar,

    // Rapporter
    canSeeReports:          isAdmin || isManager || rp.seeReports,

    // E-post
    canSendEmail:                  isAdmin || isManager || rp.sendEmail,
    canEditGlobalEmailTemplates:   isAdmin,
    canEditDeptEmailTemplates:     isAdmin || isManager,

    // Påmeldinger
    canApproveRegistrations: isAdmin || isManager || isEventManager || rp.approveRegistrations,

    // GDPR
    canRunGdpr:             isAdmin || rp.runGdpr,

    // Blokker
    canEditBlocks:          isAdmin || isManager || rp.editEvent,

    // Tilgangsnivå
    isAdmin:            isAdmin,
    isManager:          isManager,
    isSubgroupManager:  isSubgroupManager,
    isEventManager:     isEventManager,

    // Org-rolle-rettigheter (rå)
    rolePermissions:    rp,

    // Metadata
    myDepartment:            myDepartment,
    myDepartmentName:        myDepartmentName,
    editableDepartments:     editableDepartments,
    mySubgroups:             mySubgroupsList,
    accessList:              accessList,
    displayName:             user.name || user.email,
    email:                   user.email,
  };
}
const _rl = new Map();
function rateLimit(maxReq, windowMs) {
  return function(req, res, next) {
    const key = (req.headers["x-forwarded-for"] || req.ip || "unknown").split(",")[0].trim();
    const now = Date.now();
    const entry = _rl.get(key) || { count: 0, start: now };
    if (now - entry.start > windowMs) { entry.count = 0; entry.start = now; }
    entry.count++;
    _rl.set(key, entry);
    if (entry.count > maxReq) return res.status(429).json({ error: "For mange forsøk – vent litt" });
    next();
  };
}
// Clean up old state hvert 10. minutt
setInterval(function() {
  const cut = Date.now() - 600000;
  _rl.forEach(function(v, k) { if (v.start < cut) _rl.delete(k); });
}, 600000);

// ── Version ──────────────────────────────────────────────────────
// ── Static files (leaflet bundled locally) ─────────────────────
// Public config (non-secret values needed by admin frontend)
app.get("/api/config", auth, function(req, res) {
  res.json({
    ghKey: process.env.GRAPHHOPPER_KEY || "",
    domain: DOMAIN,
    adminDomain: ADMIN_DOMAIN,
  });
});

// Lab: hent filinnhold for sjekkliste-analyse
app.get("/api/lab/files", auth, adminOnly, function(req, res) {
  const fileNames = ["server.js", "index.html", "package.json"];
  const files = {};
  fileNames.forEach(function(name) {
    const fp = path.join(__dirname, name);
    try {
      if (fs.existsSync(fp)) {
        const content = fs.readFileSync(fp, "utf8").slice(0, 50000);
        files[name] = content;
      }
    } catch(e) {}
  });
  res.json({ files });
});

// Lab: filstorrelser for eksport-UI
app.get("/api/lab/export/sizes", auth, adminOnly, function(req, res) {
  const names = ["server.js","index.html","package.json","manifest-lab.json","manifest.json"];
  const sizes = {};
  names.forEach(function(n) {
    try { const fp = path.join(__dirname,n); if(fs.existsSync(fp)) sizes[n]=fs.statSync(fp).size; } catch(e) {}
  });
  try {
    let dt=0;
    ["events.json","users.json","settings.json","members.json","volunteers.json","wishes.json"].forEach(function(n){
      try{dt+=fs.statSync(path.join(DATA,n)).size;}catch(e){}
    });
    sizes["_dataTotal"]=dt;
  } catch(e) {}
  res.json(sizes);
});

// Lab: eksporter kildekode som ZIP
app.get("/api/lab/export/code", auth, adminOnly, function(req, res) {
  const allowed = ["server.js","index.html","package.json","manifest-lab.json","manifest.json"];
  const toInclude = (req.query.files||"server.js,index.html,package.json").split(",").filter(function(f){ return allowed.includes(f.trim()); });
  const entries = [];
  toInclude.forEach(function(name) {
    try { const fp=path.join(__dirname,name.trim()); if(fs.existsSync(fp)) entries.push({name:name.trim(),buf:fs.readFileSync(fp)}); } catch(e) {}
  });
  const zip = _buildZip(entries);
  const ts  = new Date().toISOString().slice(0,10);
  res.setHeader("Content-Type","application/zip");
  res.setHeader("Content-Disposition","attachment; filename=\"events-admin-code-"+ts+".zip\"");
  res.send(zip);
});

// Lab: eksporter LLM-kontekst som tekstfil
app.get("/api/lab/export/context", auth, adminOnly, function(req, res) {
  const lines = [];
  lines.push("# Events Admin - Prosjektkontekst");
  lines.push("# Generert: " + new Date().toISOString());
  lines.push("# Bruk: Lim inn i Claude/ChatGPT for kontekst om prosjektet\n");
  lines.push("## ARKITEKTUR");
  lines.push("- Backend: Node.js + Express, JSON-filer paa disk under /data");
  lines.push("- Frontend: Vanilla JS i en index.html, event delegation via ACTION_MAP");
  lines.push("- Multi-tenant: en container per org, egne volumes og env-vars");
  lines.push("- Autentisering: express-session + bcrypt");
  lines.push("- E-post: Nodemailer mot SMTP (env-vars)\n");
  lines.push("## DATAFILER (/data)");
  ["events.json","users.json","settings.json","members.json","volunteers.json",
   "wishes.json","email_log.json","inventar.json","blocks.json","series.json","devlog.json"].forEach(function(f) {
    try { const c=JSON.parse(fs.readFileSync(path.join(DATA,f),"utf8")); lines.push("- "+f+": "+(Array.isArray(c)?c.length+" items":"object")); } catch(e) { lines.push("- "+f+": (mangler)"); }
  });
  lines.push("\n## API-ENDEPUNKTER");
  try {
    const src=fs.readFileSync(path.join(__dirname,"server.js"),"utf8");
    const re=/app\.(get|post|put|delete)\("([^"]+)"/g; let m; const routes=new Set();
    while((m=re.exec(src))!==null) routes.add(m[1].toUpperCase()+" "+m[2]);
    routes.forEach(function(r){ lines.push("- "+r); });
  } catch(e) {}
  lines.push("\n## VERSJON");
  try {
    const s=getSettings(); const pkg=JSON.parse(fs.readFileSync(path.join(__dirname,"package.json"),"utf8"));
    lines.push("- Org: "+(s.siteName||"?")); lines.push("- Domene: "+(s.eventDomain||"?"));
    lines.push("- Tema: "+(s.theme||"dark")); lines.push("- Versjon: "+(pkg.version||"?"));
  } catch(e) {}
  lines.push("\n## NOKKELFUNKSJONER (index.html)");
  ["initApp() - startes etter innlogging","showPage(p) - navigerer","applySettings(s) - tema/farger",
   "loadDeltagere() - deltagerhistorikk pa tvers av events","handleDelegatedEvent(e) - ACTION_MAP",
   "buildPermissions(user) - tilganger","applyEmailVars(text,ev,reg,s) - erstatter variabler i maler"
  ].forEach(function(f){ lines.push("- "+f); });
  const ts=new Date().toISOString().slice(0,10);
  res.setHeader("Content-Type","text/plain; charset=utf-8");
  res.setHeader("Content-Disposition","attachment; filename=\"events-admin-context-"+ts+".txt\"");
  res.send(lines.join("\n"));
});

// Lab: eksporter data-snapshot som ZIP
app.get("/api/lab/export/data", auth, adminOnly, function(req, res) {
  const dfs=["events.json","users.json","settings.json","members.json","volunteers.json","wishes.json","email_log.json","inventar.json","blocks.json","series.json","devlog.json"];
  const entries=[];
  dfs.forEach(function(name) {
    const fp=path.join(DATA,name);
    try {
      if(!fs.existsSync(fp)) return;
      const raw=fs.readFileSync(fp,"utf8");
      if(name==="users.json"){ const u=JSON.parse(raw); u.forEach(function(x){x.password="[REDACTED]";}); entries.push({name,buf:Buffer.from(JSON.stringify(u,null,2))}); }
      else entries.push({name,buf:Buffer.from(raw)});
    } catch(e) {}
  });
  const zip=_buildZip(entries);
  const ts=new Date().toISOString().slice(0,10);
  res.setHeader("Content-Type","application/zip");
  res.setHeader("Content-Disposition","attachment; filename=\"events-admin-data-"+ts+".zip\"");
  res.send(zip);
});

// Minimal ZIP-builder (store method)
function _buildZip(entries) {
  const bufs=[],cds=[]; let offset=0;
  entries.forEach(function(e) {
    const name=Buffer.from(e.name),data=e.buf,crc=_crc32(data);
    const lh=Buffer.alloc(30+name.length);
    lh.writeUInt32LE(0x04034b50,0);lh.writeUInt16LE(20,4);lh.writeUInt16LE(0,6);lh.writeUInt16LE(0,8);
    lh.writeUInt16LE(0,10);lh.writeUInt16LE(0,12);lh.writeUInt32LE(crc,14);
    lh.writeUInt32LE(data.length,18);lh.writeUInt32LE(data.length,22);
    lh.writeUInt16LE(name.length,26);lh.writeUInt16LE(0,28);name.copy(lh,30);
    bufs.push(lh,data);
    const cd=Buffer.alloc(46+name.length);
    cd.writeUInt32LE(0x02014b50,0);cd.writeUInt16LE(20,4);cd.writeUInt16LE(20,6);
    cd.writeUInt16LE(0,8);cd.writeUInt16LE(0,10);cd.writeUInt16LE(0,12);cd.writeUInt16LE(0,14);
    cd.writeUInt32LE(crc,16);cd.writeUInt32LE(data.length,20);cd.writeUInt32LE(data.length,24);
    cd.writeUInt16LE(name.length,28);cd.writeUInt16LE(0,30);cd.writeUInt16LE(0,32);
    cd.writeUInt16LE(0,34);cd.writeUInt16LE(0,36);cd.writeUInt32LE(0,38);cd.writeUInt32LE(offset,42);
    name.copy(cd,46);cds.push(cd);
    offset+=lh.length+data.length;
  });
  const cdBuf=Buffer.concat(cds),eocd=Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50,0);eocd.writeUInt16LE(0,4);eocd.writeUInt16LE(0,6);
  eocd.writeUInt16LE(entries.length,8);eocd.writeUInt16LE(entries.length,10);
  eocd.writeUInt32LE(cdBuf.length,12);eocd.writeUInt32LE(offset,16);eocd.writeUInt16LE(0,20);
  return Buffer.concat([...bufs,cdBuf,eocd]);
}

function _crc32(buf) {
  let crc=0xFFFFFFFF;
  const t=_crc32.t||(_crc32.t=(function(){const a=new Uint32Array(256);for(let i=0;i<256;i++){let c=i;for(let j=0;j<8;j++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);a[i]=c;}return a;})());
  for(let i=0;i<buf.length;i++) crc=t[(crc^buf[i])&0xFF]^(crc>>>8);
  return(crc^0xFFFFFFFF)>>>0;
}

app.get("/api/version", function(req, res) {
  res.json({ version: APP_VERSION });
});

// ── Oppdateringssystem ───────────────────────────────────────────
const UPDATE_BASE     = process.env.UPDATE_URL      || "https://updates.events-admin.no";
const UPDATE_MANIFEST = process.env.UPDATE_MANIFEST || "manifest.json";
const IS_LAB          = !!(process.env.UPDATE_MANIFEST && process.env.UPDATE_MANIFEST !== "manifest.json");
const GITHUB_TOKEN    = process.env.GITHUB_TOKEN    || "";
const GITHUB_REPO     = process.env.GITHUB_REPO     || "svenskman/events-admin";

// Hjelpefunksjon: HTTP GET som fungerer på alle Node.js-versjoner
function httpGet(url, extraHeaders) {
  return new Promise(function(resolve, reject) {
    const mod = url.startsWith("https") ? require("https") : require("http");
    const opts = require("url").parse(url);
    opts.headers = Object.assign({ "User-Agent": "EventsAdmin/" + APP_VERSION }, extraHeaders || {});
    mod.get(opts, function(res) {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return httpGet(res.headers.location, extraHeaders).then(resolve).catch(reject);
      }
      const chunks = [];
      res.on("data", function(c) { chunks.push(c); });
      res.on("end",  function()  { resolve({ status: res.statusCode, body: Buffer.concat(chunks) }); });
      res.on("error", reject);
    }).on("error", reject);
  });
}

// Sjekk om oppdatering er tilgjengelig
app.get("/api/update/check", auth, adminOnly, async function(req, res) {
  try {
    const url = UPDATE_BASE + "/" + UPDATE_MANIFEST;
    const r = await httpGet(url);
    if (r.status !== 200) return res.status(502).json({ err: "Manifest ikke tilgjengelig (HTTP " + r.status + ")" });
    const manifest = JSON.parse(r.body.toString());
    const latest = manifest.version || "0.0.0";
    const hasUpdate = compareVersions(latest, APP_VERSION) > 0;
    res.json({
      current:   APP_VERSION,
      latest,
      hasUpdate,
      isLab:     IS_LAB,
      changelog: manifest.changelog || [],
      files:     manifest.files || []
    });
  } catch(e) {
    res.status(502).json({ err: "Kunne ikke kontakte oppdateringsserver: " + e.message });
  }
});

// Installer oppdatering – laster ned filer og bytter dem ut
app.post("/api/update/apply", auth, adminOnly, async function(req, res) {
  const { files, version: newVersion } = req.body;
  if (!files || !files.length) return res.status(400).json({ err: "Ingen filer angitt" });

  const crypto = require("crypto");
  const tmpDir = path.join(DATA, "_update_tmp");
  try { fs.mkdirSync(tmpDir, { recursive: true }); } catch(e) {}

  const allowedFiles = ["server.js", "index.html", "package.json"];

  try {
    // 1. Last ned til tmp
    for (const f of files) {
      if (!allowedFiles.includes(f.name))
        return res.status(400).json({ err: "Ugyldig filnavn: " + f.name });
      const r = await httpGet(f.url);
      if (r.status !== 200) throw new Error("Nedlasting feilet for " + f.name + " (HTTP " + r.status + ")");
      // Verifiser SHA256
      if (f.sha256) {
        const hash = crypto.createHash("sha256").update(r.body).digest("hex");
        if (hash !== f.sha256) throw new Error("Checksum feilet for " + f.name + "\nForventet: " + f.sha256.slice(0,12) + "…\nFikk:      " + hash.slice(0,12) + "…");
      }
      fs.writeFileSync(path.join(tmpDir, f.name), r.body);
    }

    // 2. Sikkerhetskopier gjeldende filer
    const backupDir = path.join(DATA, "_update_backup_" + APP_VERSION);
    try { fs.mkdirSync(backupDir, { recursive: true }); } catch(e) {}
    for (const f of files) {
      const src = path.join(process.cwd(), f.name);
      if (fs.existsSync(src)) {
        try { fs.copyFileSync(src, path.join(backupDir, f.name)); } catch(e) {}
      }
    }

    // 3. Patch APP_VERSION i server.js til ny versjon
    const targetVersion = req.body.version || newVersion || "unknown";
    const serverFile = files.find(function(f) { return f.name === "server.js"; });
    if (serverFile && targetVersion && targetVersion !== "unknown") {
      const serverPath = path.join(tmpDir, "server.js");
      let serverContent = fs.readFileSync(serverPath, "utf8");
      const patched = serverContent.replace(
        /const APP_VERSION\s*=\s*["'][^"']*["']/,
        'const APP_VERSION = "' + targetVersion + '"'
      );
      if (patched !== serverContent) {
        fs.writeFileSync(serverPath, patched);
        console.log("[update] Patched APP_VERSION to " + targetVersion);
      } else {
        console.warn("[update] WARNING: Could not patch APP_VERSION – pattern not found");
      }
    }

    // 4. Legg nye filer på plass
    for (const f of files) {
      const dst = path.join(process.cwd(), f.name);
      try {
        fs.copyFileSync(path.join(tmpDir, f.name), dst);
      } catch(e) {
        fs.writeFileSync(dst, fs.readFileSync(path.join(tmpDir, f.name)));
      }
    }

    // 5. Rydd opp
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch(e) {}

    res.json({ ok: true, version: targetVersion, message: "Oppdatering til v" + targetVersion + " installert! Starter om 10 sekunder…" });
    setTimeout(function() { process.exit(0); }, 10000);

  } catch(e) {
    // Auto-rollback
    try {
      const backupDir = path.join(DATA, "_update_backup_" + APP_VERSION);
      if (fs.existsSync(backupDir)) {
        for (const f of files) {
          const bak = path.join(backupDir, f.name);
          if (fs.existsSync(bak)) fs.writeFileSync(path.join(process.cwd(), f.name), fs.readFileSync(bak));
        }
      }
    } catch(re) {}
    console.error("[update/apply] Feil:", e.message);
    res.status(500).json({ err: e.message });
  }
});

// Liste tilgjengelige backups
app.get("/api/update/backups", auth, adminOnly, function(req, res) {
  try {
    const dirs = fs.readdirSync(DATA)
      .filter(function(d) { return d.startsWith("_update_backup_") && fs.statSync(path.join(DATA, d)).isDirectory(); })
      .map(function(d) {
        const version = d.replace("_update_backup_", "");
        const files   = fs.readdirSync(path.join(DATA, d));
        const stat    = fs.statSync(path.join(DATA, d));
        return { version, files, createdAt: stat.mtime };
      })
      .sort(function(a, b) { return new Date(b.createdAt) - new Date(a.createdAt); });
    res.json(dirs);
  } catch(e) { res.json([]); }
});

// Gjenopprett fra backup
app.post("/api/update/restore/:version", auth, adminOnly, function(req, res) {
  const version   = req.params.version;
  const backupDir = path.join(DATA, "_update_backup_" + version);
  if (!fs.existsSync(backupDir)) return res.status(404).json({ err: "Backup ikke funnet for v" + version });
  try {
    const files = fs.readdirSync(backupDir);
    if (!files.length) return res.status(400).json({ err: "Backup er tom" });
    // Sikkerhetskopier gjeldende
    const safeDir = path.join(DATA, "_update_backup_" + APP_VERSION + "_pre_restore");
    try { fs.mkdirSync(safeDir, { recursive: true }); } catch(e) {}
    for (const f of files) {
      const src = path.join(process.cwd(), f);
      if (fs.existsSync(src)) {
        try { fs.copyFileSync(src, path.join(safeDir, f)); } catch(e) {}
      }
    }
    // Gjenopprett
    for (const f of files) {
      fs.writeFileSync(path.join(process.cwd(), f), fs.readFileSync(path.join(backupDir, f)));
    }
    res.json({ ok: true, message: "v" + version + " gjenopprettet! Starter om 3 sekunder…" });
    setTimeout(function() { process.exit(0); }, 3000);
  } catch(e) {
    res.status(500).json({ err: "Gjenoppretting feilet: " + e.message });
  }
});

// LAB: Publiser til produksjon – oppdaterer manifest.json på GitHub
app.post("/api/update/publish", auth, adminOnly, async function(req, res) {
  if (!IS_LAB) return res.status(400).json({ err: "Kun tilgjengelig på lab-instansen" });
  const token = req.body.githubToken || GITHUB_TOKEN;
  if (!token) return res.status(400).json({ err: "GITHUB_TOKEN ikke konfigurert – lim inn token i skjemaet eller sett i docker-compose" });

  const version = req.body.version || APP_VERSION;
  const changelog = req.body.changelog || [];

  // Hjelpefunksjon: last opp én fil til GitHub
  async function githubUpload(filePath, content, commitMsg) {
    // Sjekk om filen finnes (trenger SHA for oppdatering)
    const checkR = await httpGet(
      "https://api.github.com/repos/" + GITHUB_REPO + "/contents/" + filePath,
      { "Authorization": "token " + token, "Accept": "application/vnd.github.v3+json" }
    );
    let sha = "";
    if (checkR.status === 200) {
      try { sha = JSON.parse(checkR.body.toString()).sha || ""; } catch(e) {}
    }

    const body = JSON.stringify({
      message: commitMsg,
      content: Buffer.from(content).toString("base64"),
      sha: sha || undefined
    });

    return new Promise(function(resolve, reject) {
      const https = require("https");
      const opts = {
        hostname: "api.github.com",
        path: "/repos/" + GITHUB_REPO + "/contents/" + filePath,
        method: "PUT",
        headers: {
          "Authorization": "token " + token,
          "Accept": "application/vnd.github.v3+json",
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "User-Agent": "EventsAdmin/" + APP_VERSION
        }
      };
      const req2 = https.request(opts, function(r) {
        const chunks = [];
        r.on("data", function(c) { chunks.push(c); });
        r.on("end",  function()  {
          if (r.statusCode === 200 || r.statusCode === 201) resolve(true);
          else {
            let msg = "HTTP " + r.statusCode;
            try { msg = JSON.parse(Buffer.concat(chunks).toString()).message || msg; } catch(e) {}
            reject(new Error(msg));
          }
        });
      });
      req2.on("error", reject);
      req2.write(body);
      req2.end();
    });
  }

  try {
    const crypto = require("crypto");
    const releaseDir = "releases/v" + version;
    const appFiles   = ["server.js", "index.html", "package.json"];
    const hashes     = {};
    const steps      = [];

    // 1. Last opp kode-filene til releases/vX.X.X/
    for (const name of appFiles) {
      const localPath = path.join(process.cwd(), name);
      if (!fs.existsSync(localPath)) throw new Error("Finner ikke " + name + " i /app");
      const content = fs.readFileSync(localPath);
      hashes[name] = crypto.createHash("sha256").update(content).digest("hex");
      await githubUpload(releaseDir + "/" + name, content, "v" + version + ": " + name);
      steps.push("✅ " + releaseDir + "/" + name);
      console.log("[publish] Lastet opp " + releaseDir + "/" + name);
    }

    // 2. Bygg manifest-objekt
    const manifest = {
      version,
      released: new Date().toISOString().slice(0, 10),
      changelog: changelog.length ? changelog : ["v" + version],
      files: appFiles.map(function(name) {
        return {
          name,
          url: "https://raw.githubusercontent.com/" + GITHUB_REPO + "/main/" + releaseDir + "/" + name,
          sha256: hashes[name]
        };
      })
    };

    const manifestJson = JSON.stringify(manifest, null, 2);

    // 3. Oppdater manifest-lab.json
    const labManifestFile = UPDATE_MANIFEST;
    await githubUpload(labManifestFile, manifestJson, "v" + version + " lab-manifest");
    steps.push("✅ " + labManifestFile);

    // 4. Oppdater manifest.json (prod) kun hvis req.body.publishProd
    if (req.body.publishProd) {
      await githubUpload("manifest.json", manifestJson, "Publiser v" + version + " til produksjon");
      steps.push("✅ manifest.json (prod)");
    }

    console.log("[publish] Ferdig:", steps.join(", "));
    res.json({
      ok: true,
      version,
      steps,
      hashes,
      prodPublished: !!req.body.publishProd,
      message: req.body.publishProd
        ? "v" + version + " er lastet opp og tilgjengelig for alle instanser!"
        : "v" + version + " er lastet opp til GitHub og tilgjengelig for lab-testing. Klikk 'Godkjenn til produksjon' når du er klar."
    });

  } catch(e) {
    console.error("[publish] Feil:", e.message);
    res.status(500).json({ err: e.message });
  }
});

// Hjelpefunksjon: pakk ut ZIP og returner filer
function extractZip(zipBuf) {
  const files = {};
  let i = 0;
  while (i < zipBuf.length - 4) {
    // Local file header: PK\x03\x04
    if (zipBuf[i]===0x50 && zipBuf[i+1]===0x4b && zipBuf[i+2]===0x03 && zipBuf[i+3]===0x04) {
      const compression  = zipBuf.readUInt16LE(i+8);
      const compSize     = zipBuf.readUInt32LE(i+18);
      const uncompSize   = zipBuf.readUInt32LE(i+22);
      const fnLen        = zipBuf.readUInt16LE(i+26);
      const extraLen     = zipBuf.readUInt16LE(i+28);
      const filename     = zipBuf.slice(i+30, i+30+fnLen).toString("utf8");
      const dataStart    = i+30+fnLen+extraLen;
      const dataBuf      = zipBuf.slice(dataStart, dataStart+compSize);

      // Bare hent de filene vi trenger (håndter både rotnivå og undermapper)
      const basename = filename.split("/").pop();
      if (["server.js","index.html","package.json"].includes(basename) && uncompSize > 0) {
        if (compression === 0) {
          // Stored (ingen komprimering)
          files[basename] = dataBuf;
        } else if (compression === 8) {
          // Deflate
          try {
            files[basename] = require("zlib").inflateRawSync(dataBuf);
          } catch(e) {}
        }
      }
      i = dataStart + compSize;
    } else {
      i++;
    }
  }
  return files;
}

// LAB: Last opp nye app-filer direkte via GUI (støtter enkeltfiler og ZIP)
// Bruker multer (allerede installert) istedet for busboy
const labUploadMulter = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }
}).any();

app.post("/api/update/upload", auth, adminOnly, function(req, res) {
  if (!IS_LAB) return res.status(400).json({ err: "Kun tilgjengelig på lab-instansen" });

  labUploadMulter(req, res, function(err) {
    if (err) return res.status(400).json({ err: "Opplasting feilet: " + err.message });

    const crypto = require("crypto");
    const allowedFiles = ["server.js", "index.html", "package.json"];
    const uploaded = [];
    const errors   = [];

    function saveFile(filename, buf) {
      const hash = crypto.createHash("sha256").update(buf).digest("hex");
      const dest = path.join(process.cwd(), filename);
      const backupDir = path.join(DATA, "_lab_upload_backup");
      try {
        fs.mkdirSync(backupDir, { recursive: true });
        if (fs.existsSync(dest)) fs.copyFileSync(dest, path.join(backupDir, filename));
      } catch(e) {}
      try {
        fs.writeFileSync(dest, buf);
        uploaded.push({ name: filename, size: buf.length, sha256: hash });
      } catch(e) {
        errors.push("Kunne ikke skrive " + filename + ": " + e.message);
      }
    }

    const files = req.files || [];
    if (!files.length) return res.status(400).json({ err: "Ingen filer mottatt" });

    files.forEach(function(f) {
      const filename = f.originalname;
      const buf = f.buffer;

      if (filename.toLowerCase().endsWith(".zip")) {
        try {
          const zipFiles = extractZip(buf);
          const names = Object.keys(zipFiles);
          if (!names.length) {
            errors.push("ZIP inneholder ingen kjente filer");
          } else {
            names.forEach(function(name) { saveFile(name, zipFiles[name]); });
          }
        } catch(e) {
          errors.push("ZIP-feil: " + e.message);
        }
      } else if (allowedFiles.includes(filename)) {
        saveFile(filename, buf);
      } else {
        errors.push("Ugyldig filnavn: " + filename);
      }
    });

    if (uploaded.length === 0 && errors.length > 0)
      return res.status(400).json({ err: errors.join(", ") });

    console.log("[lab-upload] Lastet opp:", uploaded.map(function(f) { return f.name; }).join(", "));
    res.json({ ok: true, uploaded, errors, message: "Filer lastet opp! Restart for å aktivere." });
  });
});

// LAB: Restart serveren (aktiverer opplastede filer)
app.post("/api/update/restart", auth, adminOnly, function(req, res) {
  if (!IS_LAB) return res.status(400).json({ err: "Kun tilgjengelig på lab-instansen" });
  res.json({ ok: true, message: "Starter om om 2 sekunder…" });
  setTimeout(function() { process.exit(0); }, 2000);
});
app.post("/api/update/approve", auth, adminOnly, async function(req, res) {
  if (!IS_LAB) return res.status(400).json({ err: "Kun tilgjengelig på lab-instansen" });
  if (!GITHUB_TOKEN) return res.status(400).json({ err: "GITHUB_TOKEN ikke konfigurert" });

  try {
    // Hent lab-manifest fra GitHub
    const labR = await httpGet(
      "https://api.github.com/repos/" + GITHUB_REPO + "/contents/" + UPDATE_MANIFEST,
      { "Authorization": "token " + token, "Accept": "application/vnd.github.v3+json" }
    );
    if (labR.status !== 200) throw new Error("Kan ikke hente lab-manifest fra GitHub");
    const labFile    = JSON.parse(labR.body.toString());
    const labContent = Buffer.from(labFile.content.replace(/\n/g, ""), "base64").toString();
    const labManifest = JSON.parse(labContent);

    // Hent SHA for manifest.json
    const prodR = await httpGet(
      "https://api.github.com/repos/" + GITHUB_REPO + "/contents/manifest.json",
      { "Authorization": "token " + token, "Accept": "application/vnd.github.v3+json" }
    );
    let prodSha = "";
    if (prodR.status === 200) {
      try { prodSha = JSON.parse(prodR.body.toString()).sha || ""; } catch(e) {}
    }

    // Skriv manifest.json = kopi av lab-manifest
    const body = JSON.stringify({
      message: "Godkjenn v" + labManifest.version + " til produksjon",
      content: Buffer.from(JSON.stringify(labManifest, null, 2)).toString("base64"),
      sha: prodSha || undefined
    });

    await new Promise(function(resolve, reject) {
      const https = require("https");
      const opts = {
        hostname: "api.github.com",
        path: "/repos/" + GITHUB_REPO + "/contents/manifest.json",
        method: "PUT",
        headers: {
          "Authorization": "token " + token,
          "Accept": "application/vnd.github.v3+json",
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "User-Agent": "EventsAdmin/" + APP_VERSION
        }
      };
      const req2 = https.request(opts, function(r) {
        const chunks = [];
        r.on("data", function(c) { chunks.push(c); });
        r.on("end", function() {
          if (r.statusCode === 200 || r.statusCode === 201) resolve();
          else {
            let msg = "HTTP " + r.statusCode;
            try { msg = JSON.parse(Buffer.concat(chunks).toString()).message || msg; } catch(e) {}
            reject(new Error(msg));
          }
        });
      });
      req2.on("error", reject);
      req2.write(body);
      req2.end();
    });

    res.json({ ok: true, version: labManifest.version, message: "v" + labManifest.version + " er nå tilgjengelig for alle produksjonsinstanser!" });
  } catch(e) {
    console.error("[approve] Feil:", e.message);
    res.status(500).json({ err: e.message });
  }
});

function compareVersions(a, b) {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i]||0) > (pb[i]||0)) return 1;
    if ((pa[i]||0) < (pb[i]||0)) return -1;
  }
  return 0;
}

// ── Auth API ─────────────────────────────────────────────────────
app.post("/api/login", rateLimit(10, 60000), async function(req, res) {
  const email    = (req.body.email || "").toLowerCase().trim();
  const password = req.body.password || "";
  if (!email || !password) return res.status(400).json({ error: "E-post og passord er påkrevd" });

  // ── Breakglass login ──
  const bgAccounts = getBreakglassAccounts();
  const bgAccount  = bgAccounts.find(function(a) { return a.email === email; });
  if (bgAccount) {
    // Timing-safe compare to prevent timing attacks
    const crypto = require("crypto");
    const pwdBuf = Buffer.from(password);
    const expBuf = Buffer.from(bgAccount.password);
    const safeMatch = pwdBuf.length === expBuf.length &&
      crypto.timingSafeEqual(pwdBuf, expBuf);
    if (!safeMatch) return res.status(401).json({ error: "Feil e-post eller passord" });

    // Log the breakglass login
    const bgLog = readJSON(BREAKGLASS_LOG_FILE);
    const bgEntry = {
      id:        require("crypto").randomBytes(6).toString("hex"),
      ts:        new Date().toISOString(),
      account:   bgAccount.index,
      email:     bgAccount.email,
      ip:        req.ip || req.connection.remoteAddress || "ukjent",
      userAgent: req.headers["user-agent"] || "ukjent",
    };
    bgLog.unshift(bgEntry);
    if (bgLog.length > 200) bgLog.length = 200;
    writeJSON(BREAKGLASS_LOG_FILE, bgLog);
    console.warn("[BREAKGLASS] Innlogging fra konto", bgAccount.index, "| IP:", bgEntry.ip);

    // Alert all admins by email
    const admins = readJSON(USERS_FILE).filter(function(u) { return u.role === "admin"; });
    const s = getSettings();
    admins.forEach(async function(admin) {
      if (!admin.email || admin.email === "[slettet]") return;
      await sendEmail({
        to: admin.email,
        subject: "🚨 BREAKGLASS-innlogging – " + bgAccount.email + " – " + new Date().toLocaleString("nb-NO"),
        html: "<div style=\"font-family:sans-serif;max-width:520px\"><div style=\"background:#7f1d1d;padding:1rem 1.5rem;border-radius:8px 8px 0 0\">" +
              "<h2 style=\"color:#fca5a5;margin:0\">🚨 Breakglass-konto aktivert</h2></div>" +
              "<div style=\"background:#1a1a1a;padding:1.5rem;border-radius:0 0 8px 8px;color:#ccc\">" +
              "<p><strong>Konto:</strong> Breakglass #" + bgAccount.index + " (" + bgAccount.email + ")</p>" +
              "<p><strong>Tidspunkt:</strong> " + new Date().toLocaleString("nb-NO") + "</p>" +
              "<p><strong>IP-adresse:</strong> " + bgEntry.ip + "</p>" +
              "<p><strong>Nettleser:</strong> " + (req.headers["user-agent"] || "ukjent").slice(0, 80) + "</p>" +
              "<p style=\"color:#f87171\">Hvis dette ikke var deg, byt breakglass-passordet umiddelbart i Portainer.</p>" +
              "</div></div>",
        text: "ADVARSEL: Breakglass-konto #" + bgAccount.index + " (" + bgAccount.email + ") logget inn " +
              new Date().toLocaleString("nb-NO") + " fra IP " + bgEntry.ip,
      });
    });

    const bgSessionData = {
      id:    "breakglass-" + bgAccount.index,
      email: bgAccount.email,
      role:  "breakglass",
      name:  "Breakglass #" + bgAccount.index,
      title: null,
      accessList: [],
    };
    req.session.regenerate(function(err) {
      if (err) return res.status(500).json({ error: "Sesjonfeil" });
      req.session.user = bgSessionData;
      req.session.save(function(err2) {
        if (err2) return res.status(500).json({ error: "Sesjonfeil" });
        res.json({ ok: true, user: Object.assign({}, bgSessionData, {
          permissions: buildBreakglassPermissions(),
        })});
      });
    });
    return;
  }

  // ── Normal login ──
  const users = readJSON(USERS_FILE);
  const user  = users.find(function(u) { return u.email === email; });
  if (!user || !(await bcrypt.compare(password, user.hash)))
    return res.status(401).json({ error: "Feil e-post eller passord" });
  const sessionData = { id: user.id, email: user.email, role: user.role, name: user.name, title: user.tittel || null, accessList: getAccessList(user) };
  req.session.regenerate(function(err) {
    if (err) { console.error("Session regenerate error:", err); return res.status(500).json({ error: "Sesjonfeil" }); }
    req.session.user = sessionData;
    req.session.save(function(err2) {
      if (err2) { console.error("Session save error:", err2); return res.status(500).json({ error: "Sesjonfeil" }); }
      var permissions = buildPermissions(user, getSettings());
      res.json({ ok: true, user: Object.assign({}, sessionData, { permissions: permissions }) });
    });
  });
});


// ══════════════════════════════════════════════════════════════════
// ── BACKUP SYSTEM ─────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════
const crypto = require("crypto");
const BACKUP_VERSION = 1;
const BACKUP_SECRET  = process.env.BACKUP_SECRET || "naf-events-default-backup-key-change-me";
if (!process.env.BACKUP_SECRET) console.warn("[SIKKERHET] BACKUP_SECRET er ikke satt! Backup-filer bruker standardnøkkel.");
const BACKUP_ALGO    = "aes-256-gcm";

// ── Derive a 32-byte key from the passphrase ──────────────────────
function deriveBackupKey(passphrase) {
  return crypto.pbkdf2Sync(passphrase, "naf-events-backup-salt-v1", 100000, 32, "sha256");
}

// ── Encrypt a JSON payload → Buffer ──────────────────────────────
function encryptBackup(payload) {
  const key = deriveBackupKey(BACKUP_SECRET);
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(BACKUP_ALGO, key, iv);
  const json    = JSON.stringify(payload);
  const enc     = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  const tag     = cipher.getAuthTag();
  // Format: [4 bytes version][16 bytes IV][16 bytes authTag][N bytes ciphertext]
  const out = Buffer.alloc(4 + 16 + 16 + enc.length);
  out.writeUInt32BE(BACKUP_VERSION, 0);
  iv.copy(out,  4);
  tag.copy(out, 20);
  enc.copy(out, 36);
  return out;
}

// ── Decrypt a Buffer → parsed JSON ───────────────────────────────
function decryptBackup(buf) {
  if (buf.length < 37) throw new Error("Ugyldig backup-fil (for kort)");
  const version = buf.readUInt32BE(0);
  if (version !== BACKUP_VERSION) throw new Error("Ukjent backup-versjon: " + version);
  const key  = deriveBackupKey(BACKUP_SECRET);
  const iv   = buf.slice(4, 20);
  const tag  = buf.slice(20, 36);
  const enc  = buf.slice(36);
  const dec  = crypto.createDecipheriv(BACKUP_ALGO, key, iv);
  dec.setAuthTag(tag);
  const json = dec.update(enc) + dec.final("utf8");
  return JSON.parse(json);
}

// ── Build backup payload for one department ───────────────────────
// Backup segments available per department
const BACKUP_SEGMENTS = {
  events:     { label: "Arrangementkalender",    desc: "Alle events, påmeldinger, innsjekk og gjestebok" },
  members:    { label: "Medlemsliste",            desc: "Medlemsregister for avdelingen" },
  volunteers: { label: "Frivillige",              desc: "Frivilligregister med oppmøtehistorikk" },
  inventar:   { label: "Inventarliste",           desc: "Utstyr og lagerbeholdning (kun full backup / admin)" },
};

function buildDeptBackup(deptId, segments) {
  const settings     = getSettings();
  const dept         = (settings.departments || []).find(function(d) { return d.id === deptId; });
  if (!dept) throw new Error("Avdeling ikke funnet: " + deptId);

  // Default: all segments except inventar (which is global/admin-only)
  const segs = segments || ["events","members","volunteers"];

  const payload = {
    backupVersion: BACKUP_VERSION,
    createdAt:     new Date().toISOString(),
    deptId:        deptId,
    deptName:      dept.name,
    siteName:      settings.siteName || "Events Admin",
    segments:      segs,
  };

  if (segs.includes("events")) {
    payload.events = readJSON(EVENTS_FILE).filter(function(e) {
      return e.department === deptId;
    });
  }
  if (segs.includes("members")) {
    payload.members = readJSON(MEMBERS_FILE).filter(function(m) {
      return m.department === deptId;
    });
  }
  if (segs.includes("volunteers")) {
    payload.volunteers = readJSON(VOLUNTEERS_FILE).filter(function(v) {
      return v.department === deptId;
    });
  }
  // inventar is global – only included by explicit admin request
  if (segs.includes("inventar")) {
    const allInv = readJSON(INVENTAR_FILE);
    // Per-dept backup: only items belonging to this dept
    payload.inventar = allInv.filter(function(i){ return !i.department || i.department === deptId; });
  }

  return payload;
}

// ── Build full-system backup (admin only) ─────────────────────────
function buildFullBackup(segments) {
  const segs = segments || ["events","members","volunteers","inventar","settings"];
  const payload = {
    backupVersion: BACKUP_VERSION,
    createdAt:     new Date().toISOString(),
    deptId:        null,
    deptName:      "Full system",
    siteName:      getSettings().siteName || "Events Admin",
    segments:      segs,
  };
  if (segs.includes("events"))     payload.events     = readJSON(EVENTS_FILE);
  if (segs.includes("members"))    payload.members    = readJSON(MEMBERS_FILE);
  if (segs.includes("volunteers")) payload.volunteers = readJSON(VOLUNTEERS_FILE);
  if (segs.includes("inventar"))   payload.inventar   = readJSON(INVENTAR_FILE);
  if (segs.includes("settings"))   payload.settings   = getSettings();
  return payload;
}

// ── Send backup email to a recipient ─────────────────────────────
async function sendBackupEmail(toEmail, deptName, backupBuf, dateStr) {
  const s        = getSettings();
  const siteName = s.siteName || "Events Admin";
  const filename = `backup_${deptName.replace(/[^a-zA-Z0-9]/g,"_")}_${dateStr}.nafbak`;
  const subject  = `🔒 Ukentlig backup – ${deptName} – ${dateStr}`;
  const html = `
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
  <div style="background:#FFD100;padding:1.25rem 2rem;border-radius:8px 8px 0 0">
    <h1 style="margin:0;font-size:1.1rem;color:#1a1a1a">${siteName}</h1>
  </div>
  <div style="background:#f9f9f9;padding:2rem;border-radius:0 0 8px 8px;border:1px solid #e0e0e0">
    <h2 style="margin-top:0;font-size:1.1rem">🔒 Ukentlig sikkerhetskopi</h2>
    <p>Vedlagt er en kryptert backup av avdeling <strong>${deptName}</strong> generert <strong>${dateStr}</strong>.</p>
    <div style="background:#fff;border-left:4px solid #FFD100;padding:.75rem 1rem;border-radius:4px;margin:1rem 0;font-size:.9rem">
      <strong>Fil:</strong> ${filename}<br>
      <strong>Format:</strong> Kryptert .nafbak (AES-256-GCM)<br>
      <strong>Gjenoppretting:</strong> Last opp filen under Innstillinger → Backup og gjenoppretting
    </div>
    <p style="color:#555;font-size:.85rem">Oppbevar filen trygt. Den inneholder personopplysninger og kan bare åpnes av dette systemet med riktig nøkkel.</p>
  </div>
</div>`;
  const text = `Ukentlig backup av ${deptName} – ${dateStr}

Fil: ${filename}
Gjenoppretting: Innstillinger → Backup og gjenoppretting

– ${siteName}`;

  const transport = getTransporter();
  if (!transport) { console.error("[backup] Ingen e-post-transport konfigurert"); return false; }

  const fromAddr = process.env.SMTP_FROM || s.emailFrom || ("noreply@" + (s.eventDomain || DOMAIN));
  try {
    await transport.sendMail({
      from: `${siteName} <${fromAddr}>`,
      to: toEmail,
      subject,
      html,
      text,
      attachments: [{
        filename,
        content: backupBuf,
        contentType: "application/octet-stream",
      }],
    });
    console.log("[backup] Sendt til:", toEmail, "avdeling:", deptName);
    return true;
  } catch(e) {
    console.error("[backup] Feil:", e.message);
    return false;
  }
}

// ── Weekly backup scheduler (runs every Monday 06:00) ─────────────
function scheduleWeeklyBackup() {
  function msUntilNextMonday6am() {
    const now  = new Date();
    const next = new Date(now);
    // Advance to next Monday
    const day = now.getDay(); // 0=Sun,1=Mon,...
    const daysUntilMon = day === 1 ? 7 : (8 - day) % 7 || 7;
    next.setDate(now.getDate() + daysUntilMon);
    next.setHours(6, 0, 0, 0);
    return next.getTime() - now.getTime();
  }

  function runWeeklyBackup() {
    const s         = getSettings();
    const users     = readJSON(USERS_FILE);
    const dateStr   = new Date().toISOString().slice(0, 10);
    const depts     = s.departments || [];

    // Find all department managers with backup e-mail enabled
    depts.forEach(async function(dept) {
      if (!dept.backupEnabled) return;
      const managers = users.filter(function(u) {
        const acc = getAccessList(u);
        return acc.some(function(a) {
          return a.department === dept.id &&
            (a.role === "department_manager" || a.role === "avdelingsleder");
        });
      });
      if (!managers.length) return;

      try {
        const payload   = buildDeptBackup(dept.id);
        const backupBuf = encryptBackup(payload);
        for (const mgr of managers) {
          if (mgr.email && mgr.email !== "[slettet]") {
            await sendBackupEmail(mgr.email, dept.name, backupBuf, dateStr);
          }
        }
      } catch(e) {
        console.error("[backup] Feil for avdeling", dept.name, ":", e.message);
      }
    });

    // Schedule next run in exactly 7 days
    setTimeout(runWeeklyBackup, 7 * 24 * 60 * 60 * 1000);
    console.log("[backup] Ukentlig backup kjørt for", dateStr);
  }

  const delay = msUntilNextMonday6am();
  setTimeout(runWeeklyBackup, delay);
  console.log("[backup] Neste ukentlig backup om",
    Math.round(delay / 1000 / 60 / 60), "timer (mandag 06:00)");
}
scheduleWeeklyBackup();

// ── API: Get available backup segments ─────────────────────────
app.get("/api/backup/segments", auth, function(req, res) {
  res.json(BACKUP_SEGMENTS);
});

// ── API: Trigger manual backup (admin or dept manager) ───────────
app.post("/api/backup/download", auth, async function(req, res) {
  const user    = req.session.user;
  const deptId  = req.body.deptId || null;
  const isAdmin = user.role === "admin";

  if (!deptId && !isAdmin) {
    return res.status(403).json({ error: "Kun admin kan lage full backup" });
  }
  if (deptId) {
    const acc = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {});
    const ok  = isAdmin || acc.some(function(a) {
      return a.department === deptId &&
        (a.role === "department_manager" || a.role === "avdelingsleder");
    });
    if (!ok) return res.status(403).json({ error: "Ingen tilgang til denne avdelingen" });
  }

  try {
    const segments  = Array.isArray(req.body.segments) ? req.body.segments : null;
    const payload   = deptId ? buildDeptBackup(deptId, segments) : buildFullBackup(segments);
    const backupBuf = encryptBackup(payload);
    const dateStr   = new Date().toISOString().slice(0, 10);
    const name      = deptId ? payload.deptName : "full";
    const filename  = `backup_${name.replace(/[^a-zA-Z0-9]/g,"_")}_${dateStr}.nafbak`;
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", "application/octet-stream");
    res.send(backupBuf);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── API: Peek at backup file (decrypt + return metadata only) ────
app.post("/api/backup/peek", auth, multer({ storage: multer.memoryStorage() }).single("backupFile"), function(req, res) {
  if (!req.file) return res.status(400).json({ error: "Ingen fil lastet opp" });
  try {
    const payload = decryptBackup(req.file.buffer);
    // Count items per segment
    const counts = {};
    if (payload.events)     counts.events     = payload.events.length;
    if (payload.members)    counts.members    = payload.members.length;
    if (payload.volunteers) counts.volunteers = payload.volunteers.length;
    if (payload.inventar)   counts.inventar   = payload.inventar.length;
    if (payload.settings)   counts.settings   = 1;
    res.json({
      backupVersion: payload.backupVersion,
      createdAt:     payload.createdAt,
      deptId:        payload.deptId,
      deptName:      payload.deptName,
      segments:      payload.segments || Object.keys(counts),
      counts,
    });
  } catch(e) {
    res.status(400).json({ error: "Kunne ikke lese filen: " + e.message });
  }
});

// ── API: Restore from backup file ─────────────────────────────────
app.post("/api/backup/restore", auth, rateLimit(5, 60000), multer({ storage: multer.memoryStorage() }).single("backupFile"), async function(req, res) {
  if (!req.file) return res.status(400).json({ error: "Ingen fil lastet opp" });
  const user    = req.session.user;
  const isAdmin = user.role === "admin";
  const mode = req.body.mode || "merge";
  if (!isAdmin) {
    const acc = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {});
    const isManager = acc.some(function(a) { return a.role === "department_manager" || a.role === "avdelingsleder"; });
    if (!isManager) return res.status(403).json({ error: "Kun avdelingsledere og admin kan gjenopprette backup" });
  } // "merge" or "replace"

  let payload;
  try {
    payload = decryptBackup(req.file.buffer);
  } catch(e) {
    return res.status(400).json({ error: "Kunne ikke dekryptere filen: " + e.message });
  }

  if (!payload.events && !payload.members && !payload.volunteers && !payload.inventar && !payload.settings) {
    return res.status(400).json({ error: "Ugyldig backup-innhold" });
  }

  // Manager: can only restore own department, never settings/inventar
  if (!isAdmin) {
    const acc2 = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {});
    const myDeptIds = acc2.filter(function(a){ return a.role === "department_manager" || a.role === "avdelingsleder"; }).map(function(a){ return a.department; });
    if (!payload.deptId || !myDeptIds.includes(payload.deptId)) {
      return res.status(403).json({ error: "Du kan kun gjenopprette backup for din egen avdeling" });
    }
    delete payload.settings;
    delete payload.inventar;
  }

  // Respect segment filter from frontend (if provided)
  let requestedSegments = null;
  try {
    if (req.body.segments) requestedSegments = JSON.parse(req.body.segments);
  } catch(e) {}
  // Filter payload to only requested segments
  if (requestedSegments) {
    if (!requestedSegments.includes("events"))     delete payload.events;
    if (!requestedSegments.includes("members"))    delete payload.members;
    if (!requestedSegments.includes("volunteers")) delete payload.volunteers;
    if (!requestedSegments.includes("inventar"))   delete payload.inventar;
    if (!requestedSegments.includes("settings"))   delete payload.settings;
  }

  const summary = { restored: 0, skipped: 0, updated: 0 };
  const restoredSegments = [];
  const dateStr = payload.createdAt ? payload.createdAt.slice(0, 10) : "ukjent";

  // ── Restore events ──
  if (payload.events && payload.events.length) {
    const current = readJSON(EVENTS_FILE);
    if (mode === "replace") {
      // Replace only events belonging to this dept (or all if full backup)
      const keep = payload.deptId
        ? current.filter(function(e) { return e.department !== payload.deptId; })
        : [];
      writeJSON(EVENTS_FILE, [...keep, ...payload.events]);
      summary.restored += payload.events.length;
    } else {
      // Merge: add missing, update existing (prefer backup version)
      const currentMap = new Map(current.map(function(e) { return [e.id, e]; }));
      payload.events.forEach(function(e) {
        if (!currentMap.has(e.id)) {
          current.push(e);
          summary.restored++;
        } else {
          // Only update if backup is newer
          const cur = currentMap.get(e.id);
          const backupDate  = new Date(e.updatedAt || e.createdAt || 0);
          const currentDate = new Date(cur.updatedAt || cur.createdAt || 0);
          if (backupDate >= currentDate) {
            const idx = current.findIndex(function(c) { return c.id === e.id; });
            current[idx] = e;
            summary.updated++;
          } else {
            summary.skipped++;
          }
        }
      });
      writeJSON(EVENTS_FILE, current);
    }
  }

  // ── Restore members ──
  if (payload.members && payload.members.length) {
    const currentM = readJSON(MEMBERS_FILE);
    if (mode === "replace" && payload.deptId) {
      const keepM = currentM.filter(function(m) { return m.department !== payload.deptId; });
      writeJSON(MEMBERS_FILE, [...keepM, ...payload.members]);
      summary.restored += payload.members.length;
    } else {
      const mMap = new Map(currentM.map(function(m) { return [m.id, m]; }));
      payload.members.forEach(function(m) {
        if (!mMap.has(m.id)) { currentM.push(m); summary.restored++; }
        else { summary.skipped++; }
      });
      writeJSON(MEMBERS_FILE, currentM);
    }
  }

  // ── Restore volunteers ──
  if (payload.volunteers && payload.volunteers.length) {
    const currentV = readJSON(VOLUNTEERS_FILE);
    if (mode === "replace" && payload.deptId) {
      const keepV = currentV.filter(function(v) { return v.department !== payload.deptId; });
      writeJSON(VOLUNTEERS_FILE, [...keepV, ...payload.volunteers]);
      summary.restored += payload.volunteers.length;
    } else {
      const vMap = new Map(currentV.map(function(v) { return [v.id, v]; }));
      payload.volunteers.forEach(function(v) {
        if (!vMap.has(v.id)) { currentV.push(v); summary.restored++; }
        else { summary.skipped++; }
      });
      writeJSON(VOLUNTEERS_FILE, currentV);
    }
  }

  // ── Restore settings (full backup only) ──
  if (payload.settings && !payload.deptId) {
    const s = getSettings();
    // Only restore safe settings fields, never overwrite auth/security
    const safe = ["siteName","contactEmail","eventDomain","showCountdown",
                  "showParticipantCount","allowSelfCheckIn","requireGuestbookApproval",
                  "emailEnabled","emailFrom","emailFromName","accentColor","departments",
                  "colors","logoUrl","theme","setupDone"];
    safe.forEach(function(k) {
      if (payload.settings[k] !== undefined) s[k] = payload.settings[k];
    });
    saveSettings(s);
  }

  // ── Restore inventar ──
  if (payload.inventar && payload.inventar.length) {
    if (mode === "replace") {
      writeJSON(INVENTAR_FILE, payload.inventar);
      summary.restored += payload.inventar.length;
    } else {
      const currentI = readJSON(INVENTAR_FILE);
      const iMap = new Map(currentI.map(function(i) { return [i.id, i]; }));
      payload.inventar.forEach(function(item) {
        if (!iMap.has(item.id)) { currentI.push(item); summary.restored++; }
        else { summary.skipped++; }
      });
      writeJSON(INVENTAR_FILE, currentI);
    }
  }

  // Track which segments were actually restored
  if (payload.events)     restoredSegments.push("events");
  if (payload.members)    restoredSegments.push("members");
  if (payload.volunteers) restoredSegments.push("volunteers");
  if (payload.inventar)   restoredSegments.push("inventar");
  if (payload.settings)   restoredSegments.push("settings");

  console.log("[backup] Gjenoppretting fra", dateStr,
    "avdeling:", payload.deptName,
    "| segments:", restoredSegments.join(","),
    "| restored:", summary.restored, "updated:", summary.updated, "skipped:", summary.skipped);

  res.json({
    ok: true,
    createdAt:        payload.createdAt,
    deptName:         payload.deptName,
    mode,
    summary,
    restoredSegments,
  });
});

// ── API: Toggle backup for department ─────────────────────────────
app.post("/api/departments/:id/backup-enabled", auth, function(req, res) {
  const user = req.session.user;
  const s    = getSettings();
  const idx  = (s.departments || []).findIndex(function(d) { return d.id === req.params.id; });
  if (idx === -1) return res.status(404).json({ error: "Ikke funnet" });

  const acc = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {});
  const ok  = user.role === "admin" || acc.some(function(a) {
    return a.department === req.params.id &&
      (a.role === "department_manager" || a.role === "avdelingsleder");
  });
  if (!ok) return res.status(403).json({ error: "Ingen tilgang" });

  s.departments[idx].backupEnabled = !!req.body.enabled;
  saveSettings(s);
  res.json({ ok: true, backupEnabled: s.departments[idx].backupEnabled });
});
// ══════════════════════════════════════════════════════════════════

// ── Breakglass API ────────────────────────────────────────────────
const breakglassOnly = function(req, res, next) {
  if (req.session.user && req.session.user.role === "breakglass") return next();
  res.status(403).json({ error: "Kun for breakglass-kontoer" });
};

// Full system restore – breakglass only
app.post("/api/breakglass/restore", auth, breakglassOnly,
  multer({ storage: multer.memoryStorage() }).single("backupFile"),
  async function(req, res) {
    if (!req.file) return res.status(400).json({ error: "Ingen fil lastet opp" });

    let payload;
    try {
      payload = decryptBackup(req.file.buffer);
    } catch(e) {
      return res.status(400).json({ error: "Kunne ikke dekryptere filen: " + e.message });
    }

    if (!payload.events && !payload.settings && !payload.members) {
      return res.status(400).json({ error: "Ugyldig backup-innhold" });
    }

    const summary = { restored: 0, files: [] };

    // Restore ALL segments unconditionally (full replace)
    if (payload.events) {
      writeJSON(EVENTS_FILE, payload.events);
      summary.restored += payload.events.length;
      summary.files.push("events (" + payload.events.length + ")");
    }
    if (payload.members) {
      writeJSON(MEMBERS_FILE, payload.members);
      summary.restored += payload.members.length;
      summary.files.push("members (" + payload.members.length + ")");
    }
    if (payload.volunteers) {
      writeJSON(VOLUNTEERS_FILE, payload.volunteers);
      summary.restored += payload.volunteers.length;
      summary.files.push("volunteers (" + payload.volunteers.length + ")");
    }
    if (payload.inventar) {
      writeJSON(INVENTAR_FILE, payload.inventar);
      summary.restored += payload.inventar.length;
      summary.files.push("inventar (" + payload.inventar.length + ")");
    }
    if (payload.settings) {
      // Never overwrite critical security settings
      const s = getSettings();
      const safe = ["siteName","contactEmail","eventDomain","showCountdown","showParticipantCount",
                    "allowSelfCheckIn","requireGuestbookApproval","emailEnabled","emailFrom",
                    "emailFromName","accentColor","departments","colors","logoUrl","theme","setupDone"];
      safe.forEach(function(k) { if (payload.settings[k] !== undefined) s[k] = payload.settings[k]; });
      saveSettings(s);
      summary.files.push("settings");
    }

    // Log the restore action
    const bgLog = readJSON(BREAKGLASS_LOG_FILE);
    bgLog.unshift({
      id:        require("crypto").randomBytes(6).toString("hex"),
      ts:        new Date().toISOString(),
      action:    "restore",
      email:     req.session.user.email,
      ip:        req.ip || req.connection.remoteAddress || "ukjent",
      backupDate: payload.createdAt || "ukjent",
      summary,
    });
    writeJSON(BREAKGLASS_LOG_FILE, bgLog);
    console.warn("[BREAKGLASS] Restore utført av", req.session.user.email,
      "| backup fra:", payload.createdAt, "| filer:", summary.files.join(", "));

    // Alert all admins
    const admins = readJSON(USERS_FILE).filter(function(u){ return u.role === "admin"; });
    const s = getSettings();
    admins.forEach(async function(admin) {
      if (!admin.email || admin.email === "[slettet]") return;
      await sendEmail({
        to: admin.email,
        subject: "🚨 Breakglass RESTORE utført – " + new Date().toLocaleString("nb-NO"),
        html: "<div style=\"font-family:sans-serif;max-width:520px\"><div style=\"background:#7f1d1d;padding:1rem 1.5rem;border-radius:8px 8px 0 0\">" +
              "<h2 style=\"color:#fca5a5;margin:0\">🚨 Full database-restore utført</h2></div>" +
              "<div style=\"background:#1a1a1a;padding:1.5rem;border-radius:0 0 8px 8px;color:#ccc\">" +
              "<p><strong>Utført av:</strong> " + req.session.user.email + "</p>" +
              "<p><strong>Backup-dato:</strong> " + (payload.createdAt || "ukjent") + "</p>" +
              "<p><strong>Tidspunkt:</strong> " + new Date().toLocaleString("nb-NO") + "</p>" +
              "<p><strong>Gjenopprettet:</strong> " + summary.files.join(", ") + "</p>" +
              "<p style=\"color:#f87171\">Systemet er nå gjenopprettet til backup-tidspunktet. Avdelingsledere kan nå kjøre sin avdelings-backup for å hente tilbake nyere data.</p>" +
              "</div></div>",
        text: "BREAKGLASS RESTORE: " + req.session.user.email + " gjenopprettet database fra " + (payload.createdAt || "ukjent"),
      });
    });

    broadcastEventUpdate(null);
    res.json({ ok: true, createdAt: payload.createdAt, summary });
  }
);

// Reset admin password – breakglass only
app.post("/api/breakglass/reset-admin-password", auth, breakglassOnly, async function(req, res) {
  const newPassword = (req.body.password || "").trim();
  if (!newPassword || newPassword.length < 12)
    return res.status(400).json({ error: "Passord må være minst 12 tegn" });

  const targetEmail = (req.body.email || "").toLowerCase().trim();
  if (!targetEmail) return res.status(400).json({ error: "E-post er påkrevd" });

  const users    = readJSON(USERS_FILE);
  const adminIdx = users.findIndex(function(u) {
    return u.email === targetEmail && u.role === "admin";
  });
  if (adminIdx === -1)
    return res.status(404).json({ error: "Admin-bruker ikke funnet: " + targetEmail });

  // Block resetting breakglass emails via this endpoint
  if (isBreakglassEmail(targetEmail))
    return res.status(403).json({ error: "Kan ikke endre breakglass-kontoer" });

  users[adminIdx].hash = await bcrypt.hash(newPassword, 12);
  writeJSON(USERS_FILE, users);

  // Log it
  const bgLog = readJSON(BREAKGLASS_LOG_FILE);
  bgLog.unshift({
    id:      require("crypto").randomBytes(6).toString("hex"),
    ts:      new Date().toISOString(),
    action:  "reset_admin_password",
    email:   req.session.user.email,
    target:  targetEmail,
    ip:      req.ip || req.connection.remoteAddress || "ukjent",
  });
  writeJSON(BREAKGLASS_LOG_FILE, bgLog);
  console.warn("[BREAKGLASS] Admin-passord tilbakestilt av", req.session.user.email, "| mål:", targetEmail);

  res.json({ ok: true, message: "Passord tilbakestilt for " + targetEmail });
});

// Breakglass log (read-only, admin only)
app.get("/api/breakglass/log", auth, adminOnly, function(req, res) {
  res.json(readJSON(BREAKGLASS_LOG_FILE));
});

// ── E-postlogg API ───────────────────────────────────────────────
app.get("/api/email-log", auth, function(req, res) {
  const me = req.session.user;
  if (me.role !== "admin") {
    const myAcc = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {});
    const isDeptMgr = myAcc.some(function(t){ return t.role === "department_manager" || t.role === "avdelingsleder"; });
    if (!isDeptMgr) return res.status(403).json({ error: "Ingen tilgang" });
  }
  const log = readJSON(EMAIL_LOG_FILE);
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  res.json(log.slice(0, limit));
});

app.delete("/api/email-log", auth, adminOnly, function(req, res) {
  writeJSON(EMAIL_LOG_FILE, []);
  res.json({ ok: true });
});

app.post("/api/email-log/test", auth, adminOnly, async function(req, res) {
  const to = (req.body.to || "").trim();
  if (!to) return res.status(400).json({ error: "E-postadresse mangler" });
  const s = getSettings();

  // Test SMTP directly – bypasses emailEnabled so we can diagnose problems
  console.log("[email-test] Forsøker å sende test til:", to);
  console.log("[email-test] SMTP_HOST:", process.env.SMTP_HOST || "(ikke satt)");
  console.log("[email-test] SMTP_USER:", process.env.SMTP_USER || "(ikke satt)");
  console.log("[email-test] SMTP_FROM:", process.env.SMTP_FROM || "(ikke satt)");

  const transport = getTransporter();
  if (!transport) {
    console.error("[email-test] Ingen transport – SMTP ikke konfigurert");
    return res.status(500).json({
      ok: false,
      error: "SMTP ikke konfigurert. Sjekk at SMTP_HOST, SMTP_USER og SMTP_PASS er satt i Portainer miljøvariabler."
    });
  }

  const fromAddr = process.env.SMTP_FROM || s.emailFrom || ("noreply@" + (s.eventDomain || DOMAIN));
  const siteName = s.siteName || "Events Admin";
  const sentAt   = new Date().toLocaleString("nb-NO");

  try {
    const info = await transport.sendMail({
      from:    (s.emailFromName || siteName) + " <" + fromAddr + ">",
      to,
      subject: "✅ Test-e-post fra " + siteName,
      html: "<div style=\"font-family:sans-serif;padding:2rem;max-width:480px;color:#1a1a1a\">" +
            "<div style=\"background:#FFD100;padding:1rem 1.5rem;border-radius:8px 8px 0 0\">" +
            "<strong>" + siteName + "</strong></div>" +
            "<div style=\"background:#f9f9f9;padding:1.5rem;border-radius:0 0 8px 8px;border:1px solid #e0e0e0\">" +
            "<h2 style=\"margin-top:0\">SMTP fungerer! 🎉</h2>" +
            "<p>Denne e-posten bekrefter at konfigurasjonen er korrekt.</p>" +
            "<table style=\"font-size:.85rem;color:#555\"><tr><td><strong>Til:&nbsp;</strong></td><td>" + to + "</td></tr>" +
            "<tr><td><strong>Fra:&nbsp;</strong></td><td>" + fromAddr + "</td></tr>" +
            "<tr><td><strong>Sendt:&nbsp;</strong></td><td>" + sentAt + "</td></tr></table>" +
            "</div></div>",
      text: "SMTP fungerer! Sendt fra " + siteName + " til " + to + " kl. " + sentAt,
    });
    writeEmailLog({ status: "sent", to, subject: "✅ Test-e-post fra " + siteName, msgId: info.messageId });
    res.json({ ok: true, to, id: info.messageId });
  } catch(e) {
    console.error("[email-test] Sendingsfeil:", e.message);
    writeEmailLog({ status: "error", to, subject: "✅ Test-e-post fra " + siteName, error: e.message });
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Glemt passord ───────────────────────────────────────────────
app.post("/api/forgot-password", rateLimit(5, 60000), function(req, res) {
  const email = (req.body.email || "").toLowerCase().trim();
  if (!email) return res.json({ ok: true }); // Alltid OK for å unngå enumeration
  const users = readJSON(USERS_FILE);
  const user  = users.find(function(u) { return u.email === email; });
  if (!user) return res.json({ ok: true });
  const tmp = Math.random().toString(36).slice(2, 10);
  const hash = bcrypt.hashSync(tmp, 10);
  user.password = hash;
  writeJSON(USERS_FILE, users);
  const s    = getSettings();
  const name = user.name || user.email;
  const adminUrl = "https://admin." + (s.eventDomain || DOMAIN);
  const subject  = "🔑 Nytt midlertidig passord – " + (s.siteName || "Events Admin");
  const html = `<div style="font-family:sans-serif;max-width:520px;margin:0 auto">
    <div style="background:#FFD100;padding:1rem 1.5rem;border-radius:8px 8px 0 0">
      <strong>${s.siteName || "Events Admin"}</strong></div>
    <div style="background:#f9f9f9;padding:1.5rem;border-radius:0 0 8px 8px;border:1px solid #e0e0e0">
      <p>Hei ${name}!</p>
      <p>Ditt midlertidige passord er: <strong style="font-size:1.2rem;letter-spacing:.05em">${tmp}</strong></p>
      <p><a href="${adminUrl}" style="background:#FFD100;color:#1a1a1a;padding:.6rem 1.25rem;border-radius:6px;text-decoration:none;font-weight:700">Logg inn →</a></p>
      <p style="color:#999;font-size:.8rem">Bytt passord under Innstillinger etter innlogging.</p>
    </div></div>`;
  const text = `Hei ${name}!\n\nMidlertidig passord: ${tmp}\nLogg inn: ${adminUrl}\n\nBytt passord etter innlogging.`;
  sendEmail({ to: email, subject, html, text }).catch(function() {});
  res.json({ ok: true });
});

app.post("/api/logout", function(req, res) {
  req.session.destroy(function() { res.json({ ok: true }); });
});

app.get("/api/me", auth, function(req, res) {
  var user = readJSON(USERS_FILE).find(function(u) { return u.id === req.session.user.id; });
  if (!user) return res.status(401).json({ error: "Ikke innlogget" });
  var permissions = buildPermissions(user, getSettings());
  res.json(Object.assign({}, req.session.user, { permissions: permissions, vehicle: user.vehicle || null }));
});

app.put("/api/me/profile", auth, async function(req, res) {
  const users = readJSON(USERS_FILE);
  const i = users.findIndex(function(u) { return u.id === req.session.user.id; });
  if (i < 0) return res.status(401).json({ error: "Ikke innlogget" });

  // Bekreft nåværende passord
  const current = req.body.currentPassword || "";
  const ok = await bcrypt.compare(current, users[i].hash);
  if (!ok) return res.status(403).json({ error: "Feil nåværende passord" });

  // E-post
  if (req.body.email) {
    const newEmail = req.body.email.toLowerCase().trim();
    const taken = users.some(function(u, j) { return j !== i && u.email === newEmail; });
    if (taken) return res.status(409).json({ error: "E-postadressen er allerede i bruk" });
    users[i].email = newEmail;
    req.session.user.email = newEmail;
  }

  // Nytt passord
  if (req.body.newPassword) {
    if (req.body.newPassword.length < 8)
      return res.status(400).json({ error: "Passord må være minst 8 tegn" });
    users[i].hash = await bcrypt.hash(req.body.newPassword, 12);
  }

  writeJSON(USERS_FILE, users);
  res.json({ ok: true, email: users[i].email });
});

// Kjøretøy – ingen passord nødvendig
app.put("/api/me/vehicle", auth, function(req, res) {
  const users = readJSON(USERS_FILE);
  const i = users.findIndex(function(u) { return u.id === req.session.user.id; });
  if (i < 0) return res.status(401).json({ error: "Ikke innlogget" });
  const v = req.body.vehicle || {};
  users[i].vehicle = {
    make:  (v.make  || "").trim().slice(0, 60),
    model: (v.model || "").trim().slice(0, 60),
    tank:  parseFloat(v.tank)  || 0,
    l100:  parseFloat(v.l100)  || 0,
    note:  (v.note  || "").trim().slice(0, 120),
  };
  writeJSON(USERS_FILE, users);
  res.json({ ok: true, vehicle: users[i].vehicle });
});

// Hent gruppe-rekkevidde for et event (minste rekkevidde blant påmeldte med kjøretøy)
app.get("/api/events/:id/group-range", auth, function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Event ikke funnet" });
  const users = readJSON(USERS_FILE);
  const regs  = ev.registrations || [];
  const staff = ev.staff || [];

  const vehicles = [];

  // 1. Kjøretøy direkte fra påmeldinger (tur-skjema)
  regs.forEach(function(r) {
    if (r.vehicle && r.vehicle.tank > 0 && r.vehicle.l100 > 0) {
      const range = Math.floor((r.vehicle.tank / r.vehicle.l100) * 100 * 0.85);
      vehicles.push({ name: r.name, make: r.vehicle.make, model: r.vehicle.model,
                      tank: r.vehicle.tank, l100: r.vehicle.l100, range, source: "reg" });
    }
  });

  // 2. Kjøretøy fra brukerkontoer (for påmeldte/stab som har konto)
  const regEmails  = new Set(regs.map(function(r) { return r.email; }));
  const staffEmails = new Set(staff.map(function(s) { return s.email; }));
  // Unngå duplikat – hopp over brukere som allerede har oppgitt via skjema
  const regEmailsWithVehicle = new Set(vehicles.map(function(v) { return; }));
  users.forEach(function(u) {
    if (u.vehicle && u.vehicle.tank > 0 && u.vehicle.l100 > 0
        && (regEmails.has(u.email) || staffEmails.has(u.email))
        && !regs.find(function(r) { return r.email === u.email && r.vehicle && r.vehicle.tank > 0; })) {
      const range = Math.floor((u.vehicle.tank / u.vehicle.l100) * 100 * 0.85);
      vehicles.push({ name: u.name, make: u.vehicle.make, model: u.vehicle.model,
                      tank: u.vehicle.tank, l100: u.vehicle.l100, range, source: "user" });
    }
  });

  if (!vehicles.length) return res.json({ range: null, limiting: null, vehicles: [] });
  vehicles.sort(function(a, b) { return a.range - b.range; });
  res.json({ range: vehicles[0].range, limiting: vehicles[0], vehicles });
});

// ── Settings API ─────────────────────────────────────────────────
app.get("/api/settings", auth, function(req, res) { res.json(getSettings()); });

app.put("/api/settings", auth, adminOnly, function(req, res) {
  const current = getSettings();
  const body    = req.body;
  // Hviteliste tillatte felt – ikke la body overskrive alt blindt
  const allowed = ["siteName","eventDomain","contactEmail","gdprRetentionDays",
    "defaultMaxParticipants","defaultRegDeadline","shiftDefaultStart","shiftDefaultEnd",
    "shiftCalStart","shiftCalEnd","emailEnabled","emailFrom","emailFromName",
    "calStartMonth","theme","logoUrl","setupDone","colors","typography",
    "regFields","orgLevels","orgRoles","departments","emailTemplates"];
  const updated = Object.assign({}, current);
  allowed.forEach(function(k) { if (body[k] !== undefined) updated[k] = body[k]; });
  if (body.gdprRetentionDays !== undefined) {
    updated.gdprRetentionDays = Math.max(30, Math.min(3650, Number(body.gdprRetentionDays) || 365));
  }
  // Sanitér siteName og eventDomain
  if (body.siteName)    updated.siteName    = (body.siteName||"").toString().slice(0,100);
  if (body.eventDomain) updated.eventDomain = (body.eventDomain||"").toString().slice(0,100).replace(/[^a-z0-9.-]/gi,"");
  saveSettings(updated);
  res.json(updated);
});

// Standard org-oppsett hvis ikke konfigurert
const DEFAULT_ORG_LEVELS = [
  { id: "central",  name: "Sentralt",  order: 0 },
  { id: "local",    name: "Lokalt",    order: 1 },
  { id: "group",    name: "Grupp",     order: 2 },
  { id: "activity", name: "Aktivitet", order: 3 }
];

const DEFAULT_ORG_ROLES = [
  {
    id: "admin", name: "Administrator", level: "central", color: "#f5c500",
    permissions: {
      createEvent: true, editEvent: true, deleteEvent: true,
      manageUsers: true, manageMembers: true, manageInventar: true,
      seeReports: true, sendEmail: true, approveRegistrations: true,
      manageDepartments: true, manageSubgroups: true, runGdpr: true
    }
  },
  {
    id: "dept_manager", name: "Avdelingsleder", level: "local", color: "#60a5fa",
    permissions: {
      createEvent: true, editEvent: true, deleteEvent: false,
      manageUsers: true, manageMembers: true, manageInventar: true,
      seeReports: true, sendEmail: true, approveRegistrations: true,
      manageDepartments: false, manageSubgroups: true, runGdpr: false
    }
  },
  {
    id: "group_manager", name: "Gruppleder", level: "group", color: "#a78bfa",
    permissions: {
      createEvent: true, editEvent: true, deleteEvent: false,
      manageUsers: false, manageMembers: true, manageInventar: false,
      seeReports: true, sendEmail: true, approveRegistrations: true,
      manageDepartments: false, manageSubgroups: false, runGdpr: false
    }
  },
  {
    id: "activity_manager", name: "Aktivitetsleder", level: "activity", color: "#4ade80",
    permissions: {
      createEvent: true, editEvent: true, deleteEvent: false,
      manageUsers: false, manageMembers: false, manageInventar: false,
      seeReports: false, sendEmail: false, approveRegistrations: true,
      manageDepartments: false, manageSubgroups: false, runGdpr: false
    }
  },
  {
    id: "volunteer", name: "Frivillig", level: "activity", color: "#888",
    permissions: {
      createEvent: false, editEvent: false, deleteEvent: false,
      manageUsers: false, manageMembers: false, manageInventar: false,
      seeReports: false, sendEmail: false, approveRegistrations: false,
      manageDepartments: false, manageSubgroups: false, runGdpr: false
    }
  }
];

// Hent org-roller fra settings eller bruk default
function getOrgRoles() {
  const s = getSettings();
  return s.orgRoles && s.orgRoles.length ? s.orgRoles : DEFAULT_ORG_ROLES;
}

function getOrgLevels() {
  const s = getSettings();
  return s.orgLevels && s.orgLevels.length ? s.orgLevels : DEFAULT_ORG_LEVELS;
}

// Hent tillatelser for en bruker basert på org-roller
function getRolePermissions(user) {
  const orgRoles = getOrgRoles();
  const accessList = getAccessList(user);

  // Admin alltid full tilgang
  if (user.role === "admin") {
    const adminRole = orgRoles.find(function(r) { return r.id === "admin"; }) || DEFAULT_ORG_ROLES[0];
    return adminRole.permissions;
  }

  // Slå sammen permissions fra alle roller brukeren har
  const merged = {
    createEvent: false, editEvent: false, deleteEvent: false,
    manageUsers: false, manageMembers: false, manageInventar: false,
    seeReports: false, sendEmail: false, approveRegistrations: false,
    manageDepartments: false, manageSubgroups: false, runGdpr: false
  };

  // Sjekk brukerens primærrolle
  const primaryRole = orgRoles.find(function(r) { return r.id === user.role || r.id === user.orgRole; });
  if (primaryRole) {
    Object.keys(merged).forEach(function(k) {
      if (primaryRole.permissions[k]) merged[k] = true;
    });
  }

  // Sjekk roller fra accessList
  accessList.forEach(function(a) {
    const roleId = a.orgRole || a.role;
    const role = orgRoles.find(function(r) {
      return r.id === roleId ||
        // Bakoverkompatibilitet med gamle roller
        (roleId === "department_manager" && r.id === "dept_manager") ||
        (roleId === "avdelingsleder"     && r.id === "dept_manager") ||
        (roleId === "subgroup_manager"   && r.id === "group_manager") ||
        (roleId === "undergruppeansvarlig" && r.id === "group_manager") ||
        (roleId === "event_manager"      && r.id === "activity_manager") ||
        (roleId === "arrangementsansvarlig" && r.id === "activity_manager");
    });
    if (role) {
      Object.keys(merged).forEach(function(k) {
        if (role.permissions[k]) merged[k] = true;
      });
    }
  });

  return merged;
}

// API: hent org-nivåer og roller
app.get("/api/org/levels", auth, function(req, res) {
  res.json(getOrgLevels());
});

app.get("/api/org/roles", auth, function(req, res) {
  res.json(getOrgRoles());
});

app.put("/api/org/roles", auth, adminOnly, function(req, res) {
  const roles = req.body.roles;
  if (!Array.isArray(roles)) return res.status(400).json({ err: "Ugyldig format" });
  if (roles.length > 20) return res.status(400).json({ err: "Maks 20 roller" });
  // Sanitér hvert rolle-objekt
  const safe = roles.map(function(r) {
    return {
      id:    (r.id    || "").toString().slice(0, 60).replace(/[^a-z0-9_-]/gi, ""),
      name:  (r.name  || "").toString().slice(0, 80),
      level: (r.level || "").toString().slice(0, 60),
      color: /^#[0-9a-fA-F]{6}$/.test(r.color || "") ? r.color : "#888888",
      permissions: typeof r.permissions === "object" && r.permissions ? r.permissions : {},
    };
  });
  const s = getSettings();
  s.orgRoles = safe;
  saveSettings(s);
  res.json({ ok: true, roles: safe });
});

app.put("/api/org/levels", auth, adminOnly, function(req, res) {
  const levels = req.body.levels;
  if (!Array.isArray(levels)) return res.status(400).json({ err: "Ugyldig format" });
  if (levels.length > 8) return res.status(400).json({ err: "Maks 8 nivåer" });
  const safe = levels.map(function(l, i) {
    return {
      id:    (l.id   || "level_"+i).toString().slice(0, 60).replace(/[^a-z0-9_-]/gi, ""),
      name:  (l.name || "Nivå "+(i+1)).toString().slice(0, 60),
      order: i,
    };
  });
  const s = getSettings();
  s.orgLevels = safe;
  saveSettings(s);
  res.json({ ok: true, levels: safe });
});

// ── Setup status (ingen auth – sjekkes ved første sidelast) ───────
app.get("/api/setup-status", function(req, res) {
  const s = getSettings();
  res.json({ setupDone: !!s.setupDone, siteName: s.siteName || "", logoUrl: s.logoUrl || "", theme: s.theme || "dark", colors: s.colors || {}, regFields: s.regFields || {} });
});

// ── Logo-opplasting + fargeekstraksjon ───────────────────────────
const logoUpload = multer({
  storage: multer.diskStorage({
    destination: function(req, file, cb) {
      const dir = path.join(DATA, "uploads");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: function(req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase() || ".png";
      cb(null, "logo" + ext);
    }
  }),
  fileFilter: function(req, file, cb) {
    cb(null, /^image\/(png|jpeg|jpg|gif|svg\+xml|webp)$/.test(file.mimetype));
  },
  limits: { fileSize: 2 * 1024 * 1024 }
});

app.post("/api/settings/logo", auth, adminOnly, logoUpload.single("logo"), function(req, res) {
  if (!req.file) return res.status(400).json({ err: "Ingen fil" });
  const logoUrl = "/logo/" + req.file.filename;

  // Farger ekstraheres i nettleseren via Canvas og sendes med requesten
  let colors = { accent: null, palette: [] };
  if (req.body.colors) {
    try { colors = JSON.parse(req.body.colors); } catch(e) {}
  }

  const s = getSettings();
  s.logoUrl = logoUrl;
  if (colors.accent) {
    if (!s.colors) s.colors = {};
    s.colors.accent = colors.accent;
  }
  saveSettings(s);
  res.json({ logoUrl, colors });
});

// Serve logo-filer
app.use("/logo", express.static(path.join(DATA, "uploads")));

// ── Avdelinger API ───────────────────────────────────────────────
function slugify(str) {
  return str.toLowerCase()
    .replace(/æ/g,"ae").replace(/ø/g,"o").replace(/å/g,"a")
    .replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,"");
}

app.get("/api/departments", auth, function(req, res) {
  res.json(getSettings().departments || []);
});

app.post("/api/departments", auth, adminOnly, function(req, res) {
  const deptName = (req.body.name || "").trim();
  if (!deptName) return res.status(400).json({ error: "Navn er påkrevd" });
  const s = getSettings();
  if (!s.departments) s.departments = [];
  if (s.departments.find(function(a) { return a.name.toLowerCase() === deptName.toLowerCase(); }))
    return res.status(409).json({ error: "Avdelingen finnes allerede" });
  s.departments.push({ id: uuid(), name: deptName, slug: slugify(deptName), subgroups: [] });
  saveSettings(s);
  broadcastEventUpdate(null);
  res.json(s.departments);
});

app.delete("/api/departments/:id", auth, adminOnly, function(req, res) {
  const s = getSettings();
  s.departments = (s.departments || []).filter(function(a) { return a.id !== req.params.id; });
  saveSettings(s);
  broadcastEventUpdate(null);
  res.json(s.departments);
});

// ── Undergrupper API ─────────────────────────────────────────────
// Department manager can administer subgroups in their own department
function ugGuard(req, res, next) {
  const u = req.session.user;
  if (!u) return res.status(401).json({ error: "Ikke innlogget" });
  if (u.role === "admin") return next();
  var myAccessList = getAccessList(readJSON(USERS_FILE).find(function(x){ return x.id === u.id; }) || {});
  var harAvdTilgang = myAccessList.some(function(t){
    return t.department === req.params.deptId && (t.role === "department_manager" || t.role === "avdelingsleder");
  });
  if (harAvdTilgang) return next();
  res.status(403).json({ error: "Ingen tilgang" });
}

app.post("/api/departments/:deptId/subgroups", auth, ugGuard, function(req, res) {
  const sgName  = (req.body.name || "").trim();
  const color = (req.body.color || "#7dff7d").trim();
  if (!sgName) return res.status(400).json({ error: "Navn er påkrevd" });
  const s = getSettings();
  const dept = (s.departments || []).find(function(a) { return a.id === req.params.deptId; });
  if (!dept) return res.status(404).json({ error: "Avdeling ikke funnet" });
  if (!dept.subgroups) dept.subgroups = [];
  if (dept.subgroups.find(function(u) { return u.name.toLowerCase() === sgName.toLowerCase(); }))
    return res.status(409).json({ error: "Undergruppen finnes allerede" });
  dept.subgroups.push({ id: uuid(), name: sgName, color: color });
  saveSettings(s);
  broadcastEventUpdate(req.params.deptId);
  res.json(dept);
});

app.delete("/api/departments/:deptId/subgroups/:sgId", auth, ugGuard, function(req, res) {
  const s = getSettings();
  const dept = (s.departments || []).find(function(a) { return a.id === req.params.deptId; });
  if (!dept) return res.status(404).json({ error: "Avdeling ikke funnet" });
  dept.subgroups = (dept.subgroups || []).filter(function(u) { return u.id !== req.params.sgId; });
  saveSettings(s);
  broadcastEventUpdate(req.params.deptId);
  res.json(dept);
});

app.put("/api/departments/:deptId/subgroups/:sgId", auth, ugGuard, function(req, res) {
  const s = getSettings();
  const dept = (s.departments || []).find(function(a) { return a.id === req.params.deptId; });
  if (!dept) return res.status(404).json({ error: "Avdeling ikke funnet" });
  const ug = (dept.subgroups || []).find(function(u) { return u.id === req.params.sgId; });
  if (!ug) return res.status(404).json({ error: "Undergruppe ikke funnet" });
  if (req.body.name)  ug.name  = req.body.name.trim();
  if (req.body.color) ug.color = req.body.color.trim();
  saveSettings(s);
  broadcastEventUpdate(req.params.deptId);
  res.json(dept);
});

app.put("/api/departments/:deptId/eventtypes/:typeId", auth, adminOnly, function(req, res) {
  const s = getSettings();
  const dept = (s.departments || []).find(function(a) { return a.id === req.params.deptId; });
  if (!dept) return res.status(404).json({ error: "Avdeling ikke funnet" });
  if (!dept.eventTyperConfig) dept.eventTyperConfig = {};
  dept.eventTyperConfig[req.params.typeId] = {
    color: req.body.color || "#7dff7d",
    label: req.body.label || req.params.typeId,
  };
  saveSettings(s);
  broadcastEventUpdate(req.params.deptId);
  res.json(dept);
});


// ── Users API ────────────────────────────────────────────────────
function userPublic(u, forAvdeling) {
  var accessList = getAccessList(u);
  if (forAvdeling) accessList = accessList.filter(function(t) { return t.department === forAvdeling; });
  return { id: u.id, email: u.email, role: u.role, name: u.name, title: u.tittel || null, accessList: accessList, createdBy: u.createdBy || null };
}

app.get("/api/users", auth, function(req, res) {
  const me = req.session.user;
  const users = readJSON(USERS_FILE);
  if (me.role === "admin") return res.json(users.map(function(u) { return userPublic(u); }));
  var myTilganger2 = getAccessList(readJSON(USERS_FILE).find(function(u) { return u.id === me.id; }) || {});
  var manageRoles = ["department_manager","avdelingsleder","subgroup_manager","undergruppeansvarlig"];
  var myManageAvdIds = myTilganger2.filter(function(t){ return manageRoles.indexOf(t.role) !== -1; }).map(function(t){ return t.department; });
  if (myManageAvdIds.length > 0) {
    // Check if caller is dept manager (sees whole dept) or only subgroup manager (sees own subgroups)
    var callerIsOnlySubMgr = myTilganger2.every(function(t){
      return t.role === "subgroup_manager" || t.role === "undergruppeansvarlig";
    }) && !myTilganger2.some(function(t){
      return t.role === "department_manager" || t.role === "avdelingsleder";
    });
    var mySubgroupIds = myTilganger2.reduce(function(acc, t){ return acc.concat(t.subgroups || []); }, []);

    var relevant = users.filter(function(u) {
      if (u.id === me.id) return true;
      var uAccess = getAccessList(u);
      // Check if user is in a dept the caller manages
      var inMyDept = uAccess.some(function(t){ return myManageAvdIds.indexOf(t.department) !== -1; });
      if (!inMyDept) return false;
      // Subgroup manager: further restrict to users in their subgroups
      if (callerIsOnlySubMgr && mySubgroupIds.length) {
        return uAccess.some(function(t){
          return myManageAvdIds.indexOf(t.department) !== -1 &&
            (t.subgroups || []).some(function(sg){ return mySubgroupIds.indexOf(sg) !== -1; });
        });
      }
      return true;
    });
    return res.json(relevant.map(function(u) {
      if (u.id === me.id) return userPublic(u);
      return userPublic(u, myManageAvdIds.find(function(id) {
        return getAccessList(u).some(function(t) { return t.department === id; });
      }));
    }));
  }
  var self = users.find(function(u) { return u.id === me.id; });
  res.json([userPublic(self || {})]);
});

// Sjekk om e-post finnes (for avdelingsleder-flyt)
app.get("/api/users/lookup", auth, function(req, res) {
  const me = req.session.user;
  var hasManageRole = me.role === "admin" || getAccessList(
    readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}
  ).some(function(t){ return ["department_manager","avdelingsleder","subgroup_manager","undergruppeansvarlig"].indexOf(t.role) !== -1; });
  if (!hasManageRole) return res.status(403).json({ error: "Ingen tilgang" });
  const email = (req.query.email || "").toLowerCase();
  const users = readJSON(USERS_FILE);
  const found = users.find(function(u) { return u.email === email; });
  if (!found) return res.json({ found: false });
  res.json({ found: true, id: found.id, name: found.name, email: found.email, role: found.role });
});

app.post("/api/users", auth, function(req, res, next) {
  if (req.session.user.role === "admin") return next();
  var me   = req.session.user;
  var myT  = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {});
  var targetDept = (req.body.newAccess || req.body.access || {}).department || req.body.department || null;

  var canCreate = false;
  myT.forEach(function(t) {
    if (t.role === "department_manager" || t.role === "avdelingsleder") {
      // Dept manager can create users for their own dept
      if (!targetDept || t.department === targetDept) canCreate = true;
    } else if (t.role === "subgroup_manager" || t.role === "undergruppeansvarlig") {
      // Subgroup manager can create users for their own dept/subgroups
      if (!targetDept || t.department === targetDept) canCreate = true;
    }
  });

  if (canCreate) {
    req.body.createdBy = me.id;
    return next();
  }
  res.status(403).json({ error: "Ingen tilgang" });
}, async function(req, res) {
  const me       = req.session.user;
  const email    = (req.body.email || "").toLowerCase();
  const password = req.body.password;
  const role     = req.body.role || "avdelingsleder";
  const name     = req.body.name || "";
  const titleValue   = req.body.tittel || null;
  const createdBy = req.body.createdBy || null;
  const newAccess = req.body.newAccess || req.body.access || null;

  if (!email) return res.status(400).json({ error: "E-post er påkrevd" });
  const users = readJSON(USERS_FILE);
  const existing = users.find(function(u) { return u.email === email; });

  if (existing) {
    if (!newAccess) return res.status(409).json({ error: "E-posten er allerede i bruk", existingId: existing.id });
    var accessList = getAccessList(existing).filter(function(t) { return t.department !== newAccess.department; });
    accessList.push(newAccess);
    existing.accessList = accessList;
    writeJSON(USERS_FILE, users);
    return res.json({ ok: true, merged: true });
  }

  if (!password) return res.status(400).json({ error: "Passord er påkrevd for nye brukere" });
  var initialAccessList = [];
  if (newAccess) initialAccessList.push(newAccess);
  else if (req.body.department) initialAccessList.push({ department: req.body.department, subgroups: Array.isArray(req.body.subgroups) ? req.body.subgroups : [], eventTyper: Array.isArray(req.body.eventTyper) ? req.body.eventTyper : [] });
  users.push({ id: uuid(), email, hash: await bcrypt.hash(password, 12), role, name, title: titleValue, accessList: initialAccessList, createdBy });
  writeJSON(USERS_FILE, users);
  res.json({ ok: true, merged: false });
});

app.put("/api/users/:id", auth, async function(req, res) {
  const users = readJSON(USERS_FILE);
  // Breakglass accounts are provisioned via env vars – block any UI changes
  const targetUser = users.find(function(u){ return u.id === req.params.id; });
  if (targetUser && isBreakglassEmail(targetUser.email))
    return res.status(403).json({ error: "Breakglass-kontoer kan ikke endres via UI – bruk Portainer miljøvariabler" });

  const i = users.findIndex(function(u) { return u.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  const me = req.session.user;

  if (me.role !== "admin") {
    var myAccess2 = getAccessList(readJSON(USERS_FILE).find(function(u) { return u.id === me.id; }) || {});
    var myManageDepts = myAccess2.filter(function(t){
      return t.role === "department_manager" || t.role === "avdelingsleder" ||
             t.role === "subgroup_manager"   || t.role === "undergruppeansvarlig";
    }).map(function(t){ return t.department; });

    // Can always edit yourself
    var editingSelf = users[i].id === me.id;
    // Can edit others only if they are in a dept you manage
    var targetInMyDept = !editingSelf && getAccessList(users[i]).some(function(t){
      return myManageDepts.indexOf(t.department) !== -1;
    });

    if (!editingSelf && !targetInMyDept)
      return res.status(403).json({ error: "Ingen tilgang til denne brukeren" });

    // Non-admin cannot elevate to admin or department_manager
    if (req.body.role === "admin" || req.body.role === "department_manager")
      return res.status(403).json({ error: "Kan ikke tildele denne rollen" });

    // Subgroup manager cannot promote beyond their own level
    var iAmOnlySubMgr = myAccess2.every(function(t){
      return t.role === "subgroup_manager" || t.role === "undergruppeansvarlig";
    });
    if (iAmOnlySubMgr && (req.body.newAccess || req.body.access)) {
      var newRole = (req.body.newAccess || req.body.access).role || "";
      if (newRole === "department_manager" || newRole === "avdelingsleder")
        return res.status(403).json({ error: "Undergruppeleder kan ikke gi avdelingsleder-tilgang" });
    }
  }

  if (req.body.name   !== undefined) users[i].name   = req.body.name;
  if (req.body.tittel !== undefined || req.body.titleValue !== undefined) users[i].tittel = req.body.titleValue || req.body.tittel || null;
  if (req.body.role   !== undefined && me.role === "admin") users[i].role = (req.body.role||"").toLowerCase().replace(/[- ]/g,"_");
  if (req.body.password) users[i].hash = await bcrypt.hash(req.body.password, 12);

  if (req.body.newAccess || req.body.access) {
    var t = req.body.newAccess || req.body.access;
    var myAvdIds3 = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
    if (me.role !== "admin" && myAvdIds3.indexOf(t.department) === -1)
      return res.status(403).json({ error: "Kan ikke endre tilgang for andre avdelinger" });
    var rest = getAccessList(users[i]).filter(function(x) { return x.department !== t.department; });
    rest.push(t);
    users[i].accessList = rest;
  }
  if (req.body.accessList !== undefined && me.role === "admin") users[i].accessList = req.body.accessList;

  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

app.delete("/api/users/:id", auth, function(req, res) {
  const me = req.session.user;
  const users = readJSON(USERS_FILE);
  const target = users.find(function(u) { return u.id === req.params.id; });
  if (!target) return res.status(404).json({ error: "Ikke funnet" });
  // Block deletion of breakglass accounts
  if (isBreakglassEmail(target.email))
    return res.status(403).json({ error: "Breakglass-kontoer kan ikke slettes – administreres via Portainer" });

  if (me.role === "admin") {
    writeJSON(USERS_FILE, users.filter(function(u) { return u.id !== req.params.id; }));
    return res.json({ ok: true });
  }
  // Department manager can remove users from their own departments
  // Subgroup manager can remove users from their own subgroups
  var myAccDel = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {});
  var isDeptMgr = myAccDel.some(function(t){ return t.role === "department_manager" || t.role === "avdelingsleder"; });
  var isSubMgr  = myAccDel.some(function(t){ return t.role === "subgroup_manager"  || t.role === "undergruppeansvarlig"; });

  if (isDeptMgr || isSubMgr) {
    var myDeptsDel = myAccDel.map(function(t){ return t.department; });
    // Can only act on users in departments the caller manages
    var targetInMyDept = getAccessList(target).some(function(x){ return myDeptsDel.indexOf(x.department) !== -1; });
    if (!targetInMyDept) return res.status(403).json({ error: "Ingen tilgang til denne brukeren" });

    // Remove only the access entries that belong to caller's departments
    var remaining = getAccessList(target).filter(function(x){ return myDeptsDel.indexOf(x.department) === -1; });
    if (remaining.length === 0) {
      writeJSON(USERS_FILE, users.filter(function(u){ return u.id !== req.params.id; }));
    } else {
      target.accessList = remaining;
      writeJSON(USERS_FILE, users);
    }
    return res.json({ ok: true });
  }
  res.status(403).json({ error: "Ingen tilgang" });
});

// ── Events API ───────────────────────────────────────────────────

// SSE-strøm: klienter kobler til for live-oppdateringer
app.get("/api/events/stream", function(req, res) {
  const department = req.query.department || null;
  const clientId = sseNextId++;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();

  // Send en ping med en gang for å bekrefte tilkobling
  res.write("data: " + JSON.stringify({ type: "connected", clientId }) + "\n\n");

  sseClients.set(clientId, { res, department });

  // Keepalive hvert 25 sek
  const keepalive = setInterval(function() {
    try { res.write(": keepalive\n\n"); } catch(e) {}
  }, 25000);

  req.on("close", function() {
    clearInterval(keepalive);
    sseClients.delete(clientId);
  });
});

app.get("/api/events", auth, function(req, res) {
  var user = req.session.user;
  var myAvds = getUserDepartments(user);
  res.json(readJSON(EVENTS_FILE).filter(function(e) {
    // Admin ser alt
    if (user.role === "admin") return true;
    // Ikke-admin uten noen avdelinger ser ingenting
    if (!myAvds.length) return false;
    // Event må tilhøre en av brukerens avdelinger (eller være collaborator)
    if (e.department && myAvds.includes(e.department)) return true;
    // Vis events der bruker er collaborator (invitert fra annen avdeling)
    return (e.collaborators || []).some(function(c) {
      return myAvds.includes(c.departmentId) && (c.status === "accepted" || c.status === "pending");
    });
  }).map(function(e) {
    var isCollabGuest = !canEditEvent(e, user) && (e.collaborators || []).some(function(c) {
      return myAvds.includes(c.departmentId);
    });
    var myCollabAvdId = isCollabGuest
      ? (e.collaborators || []).find(function(c) { return myAvds.includes(c.departmentId); }).departmentId
      : null;
    var collabStatus = isCollabGuest
      ? (e.collaborators || []).find(function(c) { return myAvds.includes(c.departmentId); }).status
      : null;
    return Object.assign({}, e, {
      registrationCount: (e.registrations || []).length,
      canEdit: canEditEvent(e, user),
      isCollabGuest:  isCollabGuest,
      myCollabAvdId:  myCollabAvdId,
      collabStatus:   collabStatus,
      // Fjern sensitiv data fra andre avdelingers staff
      guestStaff:  e.guestStaff  || {},
      guestShifts: e.guestShifts || {},
    });
  }));
});

app.get("/api/events/:id", function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  // Offentlig endpoint – aldri send sensitiv data
  const isAuth = !!req.session.user;
  if (isAuth) {
    // Innlogget admin/personal: send alt unntatt cancelToken og checkinPin i registrations
    var safeEv = Object.assign({}, ev);
    safeEv.registrations = (ev.registrations || []).map(function(r) {
      var safe = Object.assign({}, r);
      delete safe.cancelToken;
      return safe;
    });
    return res.json(safeEv);
  }
  // Offentlig: send kun metadata uten persondata
  res.json({
    id: ev.id, slug: ev.slug, title: ev.title, description: ev.description,
    date: ev.date, endDate: ev.endDate, endTime: ev.endTime, location: ev.location,
    eventType: ev.eventType, image: ev.image,
    maxParticipants: ev.maxParticipants,
    registrationCount: (ev.registrations||[]).filter(function(r){return !r.anonymized;}).length,
    showParticipants: ev.showParticipants, isPublic: ev.isPublic,
    hasPin: !!ev.staffPin, department: ev.department, lottery: ev.lottery ? {
      enabled: !!ev.lottery.enabled, prize: ev.lottery.prize||"", type: ev.lottery.type||"trekning"
    } : null,
    route: ev.route || null, roomplan: ev.roomplan || null,
  });
});

app.post("/api/events", auth, managerOrAdmin, upload.single("image"), function(req, res) {
  const title       = (req.body.title || "").trim().slice(0, 200);
  const description = (req.body.description || "").slice(0, 5000);
  const date        = req.body.date;
  const location    = (req.body.location || "").slice(0, 200);
  const maxP        = Number(req.body.maxParticipants) || 0;
  const showP       = req.body.showParticipants === "true";
  const isPublic    = req.body.isPublic === "true";
  if (!title) return res.status(400).json({ error: "Tittel er påkrevd" });
  const s = getSettings();
  const evDomain = s.eventDomain || DOMAIN;
  const users = readJSON(USERS_FILE);
  const creator = users.find(function(u) { return u.id === req.session.user.id; });
  // Department: use explicit value from request, otherwise user's department
  var ct = creator ? getAccessList(creator) : [];
  const eventDept = req.body.department || (ct.length ? ct[0].department : null);
  const subgroup = req.body.subgroup || null;

  // Get name for department and subgroup for slug
  const deptObj = eventDept ? (s.departments || []).find(function(a){ return a.id === eventDept; }) : null;
  const ugObj  = (deptObj && subgroup) ? (deptObj.subgroups || []).find(function(u){ return u.id === subgroup; }) : null;

  function toSlugPart(str) {
    return (str || "").toLowerCase()
      .replace(/æ/g,"ae").replace(/ø/g,"o").replace(/å/g,"a")
      .replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,"");
  }
  const parts = [toSlugPart(title)];
  if (deptObj) parts.push(toSlugPart(deptObj.name));
  if (ugObj)  parts.push(toSlugPart(ugObj.name));
  if (date)   parts.push(new Date(date).getFullYear());
  const baseSlug = parts.join("-");

  const events = readJSON(EVENTS_FILE);
  var slug = baseSlug;
  var counter = 2;
  while (events.find(function(e) { return e.slug === slug; })) {
    slug = baseSlug + "-" + counter++;
  }
  const ev = {
    id: uuid(), slug: slug, title: title, description: description,
    date: date || null, location: location, maxParticipants: maxP, showParticipants: showP,
    isPublic: isPublic,
    isInternal:    req.body.isInternal === "true",
    internalNote:  (req.body.internalNote || "").slice(0, 5000),
    emailTemplate: req.body.emailTemplate || "default",
    eventType: ["kurs","tur"].indexOf(req.body.eventType) !== -1 ? req.body.eventType : "stand",
    endTime: req.body.endTime ? req.body.endTime.trim() : null,
    endDate: req.body.endDate ? req.body.endDate.trim() : null,
    image: req.file ? "/uploads/" + path.basename(req.file.filename) : null,
    registrations: [], staff: [], guestbook: [],
    url: "https://" + slug + "." + evDomain,
    createdAt: new Date().toISOString(),
    createdBy: req.session.user.email,
    department: eventDept,
    subgroup: subgroup,
    staffPin: req.body.staffPin ? req.body.staffPin.trim() : null,
    isFinalized: req.body.isFinalized === "true",
    seriesId: req.body.seriesId || null,
    lottery: (function() {
      try { const l = JSON.parse(req.body.lottery || "null"); return l && l.enabled !== undefined ? { enabled: !!l.enabled, mode: l.mode || "manual", prize: (l.prize || "").slice(0, 100), winners: [] } : null; }
      catch(e) { return null; }
    })(),
  };
  events.push(ev);
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(eventDept);
  res.json(ev);
});

app.put("/api/events/:id", auth, managerOrAdmin, upload.single("image"), function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const i = events.findIndex(function(e) { return e.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  if (!canEditEvent(events[i], req.session.user))
    return res.status(403).json({ error: "Du kan bare redigere dine egne events" });
  if (req.body.title            !== undefined) events[i].title           = (req.body.title || "").trim().slice(0, 200);
  if (req.body.description      !== undefined) events[i].description     = (req.body.description || "").slice(0, 5000);
  if (req.body.date             !== undefined) events[i].date            = req.body.date || null;
  if (req.body.location         !== undefined) events[i].location        = (req.body.location || "").slice(0, 200);
  if (req.body.maxParticipants  !== undefined) events[i].maxParticipants = Number(req.body.maxParticipants);
  if (req.body.showParticipants !== undefined) events[i].showParticipants = req.body.showParticipants === "true";
  if (req.body.isPublic         !== undefined) events[i].isPublic         = req.body.isPublic === "true";
  if (req.body.isInternal       !== undefined) events[i].isInternal       = req.body.isInternal === "true";
  if (req.body.internalNote     !== undefined) events[i].internalNote     = (req.body.internalNote || "").slice(0, 5000);
  if (req.body.emailTemplate    !== undefined) events[i].emailTemplate    = req.body.emailTemplate || "default";
  if (req.body.eventType        !== undefined) events[i].eventType       = ["kurs","tur"].indexOf(req.body.eventType) !== -1 ? req.body.eventType : "stand";
  if (req.body.department    !== undefined)               events[i].department       = req.body.department || null;
  if (req.body.subgroup !== undefined)               events[i].subgroup    = req.body.subgroup || null;
  if (req.file)                                events[i].image           = "/uploads/" + path.basename(req.file.filename);
  if (req.body.staffPin !== undefined)         events[i].staffPin        = req.body.staffPin ? req.body.staffPin.trim() : null;
  if (req.body.isFinalized !== undefined)      events[i].isFinalized     = req.body.isFinalized === "true";
  if (req.body.endTime  !== undefined)         events[i].endTime         = req.body.endTime ? req.body.endTime.trim() : null;
  if (req.body.endDate  !== undefined)         events[i].endDate         = req.body.endDate ? req.body.endDate.trim() : null;
  if (req.body.seriesId  !== undefined)          events[i].seriesId         = req.body.seriesId || null;
  if (req.body.lottery !== undefined) {
    try {
      const l = JSON.parse(req.body.lottery || "null");
      if (l && l.enabled !== undefined) {
        const existing = events[i].lottery || {};
        events[i].lottery = {
          enabled:  !!l.enabled,
          mode:     l.mode || "manual",
          prize:    (l.prize || "").slice(0, 100),
          winners:  existing.winners || [],
          lastDraw: existing.lastDraw || null,
        };
      }
    } catch(e) {}
  }
  if (!events[i].staff)     events[i].staff     = [];
  if (!events[i].guestbook) events[i].guestbook = [];
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(events[i].department);
  res.json(events[i]);
});

app.delete("/api/events/:id", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!canEditEvent(ev, req.session.user))
    return res.status(403).json({ error: "Du kan bare slette dine egne events" });
  const dept = ev.department;
  writeJSON(EVENTS_FILE, events.filter(function(e) { return e.id !== req.params.id; }));
  broadcastEventUpdate(dept);
  res.json({ ok: true });
});

// ── Lottery API ──────────────────────────────────────────────────



app.get("/api/events/:id/registrations", auth, function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  res.json(ev.registrations || []);
});

// ── Lottery API ──────────────────────────────────────────────────
// Registrer deltaker til lotteri/konkurranse via fullskjerm-modus
app.post("/api/events/:id/lottery/register", rateLimit(10, 60000), function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const i = events.findIndex(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  const ev = events[i];
  if (!ev.lottery || !ev.lottery.enabled) return res.status(400).json({ error: "Konkurranse ikke aktiv" });
  const name = (req.body.name || "").trim().slice(0, 100);
  const meta = (req.body.meta || "").trim().slice(0, 300);
  if (!name) return res.status(400).json({ error: "Navn er påkrevd" });
  if (!ev.registrations) ev.registrations = [];
  // Unngå duplikater på navn (innen siste time)
  const existing = ev.registrations.find(function(r) {
    return r.name.toLowerCase() === name.toLowerCase() && !r.anonymized;
  });
  if (existing) return res.status(400).json({ error: "Du er allerede registrert!" });
  const reg = {
    id: uuid(), name, email: "", phone: "", meta,
    registeredAt: new Date().toISOString(), lotteryEntry: true
  };
  ev.registrations.push(reg);
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true, id: reg.id });
});

app.post("/api/events/:id/lottery/draw", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const i = events.findIndex(function(e) { return e.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  const ev = events[i];
  if (!ev.lottery || !ev.lottery.enabled)
    return res.status(400).json({ error: "Lotteri er ikke aktivert for dette eventet" });
  const regs = ev.registrations || [];
  const prevWinnerIds = new Set((ev.lottery.winners || []).map(function(w) { return w.regId; }));
  const eligible = regs.filter(function(r) { return !r.anonymized && !prevWinnerIds.has(r.id); });
  if (!eligible.length)
    return res.status(400).json({ error: "Ingen kvalifiserte deltagere igjen" });
  const winner = eligible[Math.floor(Math.random() * eligible.length)];
  const draw = {
    regId:   winner.id,
    name:    winner.name,
    meta:    winner.meta || "",
    drawnAt: new Date().toISOString(),
    drawnBy: req.session.user.email,
    prize:   ev.lottery.prize || "",
    drawNum: (ev.lottery.winners || []).length + 1
  };
  if (!ev.lottery.winners) ev.lottery.winners = [];
  ev.lottery.winners.push(draw);
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true, winner: draw, remaining: eligible.length - 1 });
});

app.get("/api/events/:id/lottery/winners", function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  res.json({ winners: (ev.lottery && ev.lottery.winners) || [], lottery: ev.lottery || null });
});

app.delete("/api/events/:id/lottery/winners", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const i = events.findIndex(function(e) { return e.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  if (events[i].lottery) events[i].lottery.winners = [];
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(events[i].department);
  res.json({ ok: true });
});

app.get("/api/events/:id/lottery", function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const regs    = ev.registrations || [];
  const lottery = ev.lottery || { enabled: false };
  const winnerIds = new Set((lottery.winners || []).map(function(w) { return w.regId; }));
  const eligible  = regs.filter(function(r) { return !r.anonymized && !winnerIds.has(r.id); }).length;
  res.json({
    enabled:  !!lottery.enabled,
    mode:     lottery.mode || "manual",
    prize:    lottery.prize || "",
    winners:  lottery.winners || [],
    lastDraw: lottery.lastDraw || null,
    total:    regs.length,
    eligible: eligible,
  });
});

// ── Romplan API ───────────────────────────────────────────────────
app.get("/api/events/:id/roomplan", auth, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ err: "Ikke funnet" });
  res.json(ev.roomplan || { items: [], roomW: 10, roomH: 8 });
});

app.put("/api/events/:id/roomplan", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const i = events.findIndex(function(e) { return e.id === req.params.id; });
  if (i < 0) return res.status(404).json({ err: "Ikke funnet" });
  events[i].roomplan = {
    items: req.body.items || [],
    roomW: parseFloat(req.body.roomW) || 10,
    roomH: parseFloat(req.body.roomH) || 8,
    updatedAt: new Date().toISOString()
  };
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

// ── Inndatavalidering ─────────────────────────────────────────────
function validateName(s) {
  if (!s) return false;
  return /^[\p{L}\s'\-\.]{1,100}$/u.test(s);
}
function validateEmail(s) {
  if (!s) return false;
  return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(s) && s.length <= 200;
}
function validatePhone(s) {
  if (!s) return true;
  return /^[\d\s+\-().]{0,30}$/.test(s);
}
function validateVehicleText(s) {
  if (!s) return true;
  return /^[\p{L}\d\s\-]{0,60}$/u.test(s);
}
function sanitizeName(s)  { return (s || "").trim().slice(0, 100); }
function sanitizePhone(s) { return (s || "").replace(/[^\d\s+\-().]/g, "").trim().slice(0, 30); }

app.post("/api/events/:id/register", rateLimit(10, 60000), function(req, res) {
  const name  = sanitizeName(req.body.name);
  const email = (req.body.email || "").toLowerCase().trim().slice(0, 200);
  const phone = sanitizePhone(req.body.phone);
  if (!name || !email) return res.status(400).json({ error: "Navn og e-post er påkrevd" });
  if (!validateName(name))  return res.status(400).json({ error: "Navn inneholder ugyldige tegn" });
  if (!validateEmail(email)) return res.status(400).json({ error: "Ugyldig e-postadresse" });
  if (!validatePhone(phone)) return res.status(400).json({ error: "Telefonnummer inneholder ugyldige tegn" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Event ikke funnet" });
  if (!ev.registrations) ev.registrations = [];
  if (ev.maxParticipants && ev.registrations.length >= ev.maxParticipants)
    return res.status(400).json({ error: "Fullt – ingen ledige plasser" });
  if (ev.registrations.find(function(r) { return r.email === email.toLowerCase(); }))
    return res.status(409).json({ error: "Denne e-postadressen er allerede påmeldt" });

  // Kjøretøydata fra tur-påmelding
  var _existingPins = new Set((ev.registrations || []).map(function(r) { return r.checkinPin; }));
  var _pin; do { _pin = String(Math.floor(1000 + Math.random() * 9000)); } while (_existingPins.has(_pin));
  const _cancelToken = require("crypto").randomBytes(24).toString("hex");
  const reg = { id: uuid(), name: name, email: email.toLowerCase(), phone: phone, registeredAt: new Date().toISOString(), checkinPin: _pin, cancelToken: _cancelToken };
  if (req.body.walkin) {
    reg.walkin = true;
    reg.checkedIn = true;
    reg.checkedInAt = new Date().toISOString();
  }
  if (req.body.vehicle && req.body.vehicle.make) {
    const v = req.body.vehicle;
    const vMake  = (v.make  || "").trim().slice(0, 60);
    const vModel = (v.model || "").trim().slice(0, 60);
    if (!validateVehicleText(vMake) || !validateVehicleText(vModel))
      return res.status(400).json({ error: "Motorsykkelfeltet inneholder ugyldige tegn" });
    reg.vehicle = {
      make:  vMake,
      model: vModel,
      tank:  Math.max(0, Math.min(200, parseFloat(v.tank) || 0)),
      l100:  Math.max(0, Math.min(50,  parseFloat(v.l100) || 0)),
    };
  }
  // Hotellrom-preferanse (tur med overnatting)
  if (req.body.hotelRoom && ["enkel", "dobbelt"].includes(req.body.hotelRoom)) {
    reg.hotelRoom = req.body.hotelRoom;
  }
  ev.registrations.push(reg);
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  const _defaultTpl = (ev.eventType === "stand") ? "interest" : "registration";
  const _tplType = (ev.emailTemplate && ev.emailTemplate !== "default") ? ev.emailTemplate : _defaultTpl;
  const _cancelUrl = "https://" + ev.slug + "." + (getSettings().eventDomain || DOMAIN) + "/avmeld?token=" + _cancelToken;
  let mail;
  if (ev.isFinalized && ev.eventType === "tur") {
    mail = emailTurFinalized(ev, { name, email, hotelRoom: reg.hotelRoom || null, cancelUrl: _cancelUrl }, getSettings());
  } else {
    mail = emailRegConfirmation(Object.assign({}, ev, { emailTemplate: _tplType }), { name, email, checkinPin: _pin, cancelUrl: _cancelUrl }, getSettings());
  }
  sendEmail({ to: email, subject: mail.subject, html: mail.html, text: mail.text }).catch(() => {});
  res.json({ ok: true });
});

// ── Avmelding via token (offentlig) ─────────────────────────────
app.get("/avmeld", function(req, res) {
  const token = (req.query.token || "").trim();
  if (!token) return res.status(400).send(cancelPageHtml(null, null, "missing_token"));
  const events = readJSON(EVENTS_FILE);
  let foundEv = null, foundReg = null;
  events.forEach(function(ev) {
    (ev.registrations || []).forEach(function(r) {
      if (r.cancelToken === token && !r.anonymized) { foundEv = ev; foundReg = r; }
    });
  });
  if (!foundEv) return res.send(cancelPageHtml(null, null, "invalid_token"));
  if (foundReg.cancelledAt) return res.send(cancelPageHtml(foundEv, foundReg, "already_cancelled"));
  res.send(cancelPageHtml(foundEv, foundReg, "confirm"));
});

// ── Avmelding via token (POST) ────────────────────────────────────
app.post("/avmeld", rateLimit(10, 60000), function(req, res) {
  const token = (req.query.token || req.body.token || "").trim();
  if (!token) return res.status(400).send(cancelPageHtml(null, null, "missing_token"));
  const events = readJSON(EVENTS_FILE);
  let foundEv = null, foundReg = null, evIdx = -1, regIdx = -1;
  events.forEach(function(ev, ei) {
    (ev.registrations || []).forEach(function(r, ri) {
      if (r.cancelToken === token && !r.anonymized) {
        foundEv = ev; foundReg = r; evIdx = ei; regIdx = ri;
      }
    });
  });
  if (!foundEv) return res.send(cancelPageHtml(null, null, "invalid_token"));
  if (foundReg.cancelledAt) return res.send(cancelPageHtml(foundEv, foundReg, "already_cancelled"));
  // Fjern påmeldingen
  events[evIdx].registrations.splice(regIdx, 1);
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(foundEv.department);
  // Send avmeldingsbekreftelse
  if (foundReg.email) {
    const mail = emailCancellationConfirmation(foundEv, foundReg, getSettings());
    sendEmail({ to: foundReg.email, subject: mail.subject, html: mail.html, text: mail.text }).catch(() => {});
  }
  res.send(cancelPageHtml(foundEv, foundReg, "done"));
});

// ── Avmeldingsside HTML ───────────────────────────────────────────
function cancelPageHtml(ev, reg, state) {
  const s = getSettings();
  const siteName = s.siteName || "Events Admin";
  const accent = s.accentColor || "#FFD100";
  const token = reg && reg.cancelToken ? reg.cancelToken : "";
  const messages = {
    confirm: {
      title: "Avmeld deg",
      body: `<p>Du er påmeldt <strong>${escHtml(ev.title)}</strong>.</p>`
           + `<p style="color:#555;font-size:.9rem">Er du sikker på at du vil avmelde deg?</p>`
           + `<form method="POST" action="/avmeld?token=${encodeURIComponent(token)}">`
           + `<button type="submit" style="background:#e53e3e;color:#fff;border:none;padding:.75rem 2rem;`
           + `border-radius:6px;font-size:1rem;font-weight:700;cursor:pointer;margin-top:1rem">Ja, avmeld meg</button>`
           + `<a href="https://${escHtml(ev.slug)}.${escHtml(s.eventDomain || DOMAIN)}" `
           + `style="display:inline-block;margin-left:1rem;color:#888;font-size:.9rem">Nei, gå tilbake</a></form>`,
    },
    done: {
      title: "Avmeldt",
      body: `<p>Du er nå avmeldt fra <strong>${escHtml(ev.title)}</strong>.</p>`
           + `<p style="color:#555;font-size:.9rem">En bekreftelse er sendt til ${escHtml(reg.email)}.</p>`,
    },
    already_cancelled: {
      title: "Allerede avmeldt",
      body: `<p>Denne påmeldingen er allerede avmeldt.</p>`,
    },
    invalid_token: {
      title: "Ugyldig lenke",
      body: `<p>Lenken er ugyldig eller utløpt.</p>`,
    },
    missing_token: {
      title: "Mangler token",
      body: `<p>Ingen avmeldingstoken funnet i lenken.</p>`,
    },
  };
  const msg = messages[state] || messages.invalid_token;
  return `<!DOCTYPE html><html lang="no"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escHtml(msg.title)} – ${escHtml(siteName)}</title>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:"Helvetica Neue",Arial,sans-serif;background:#1a1a1a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem}
      .card{background:#2a2a2a;border-radius:12px;max-width:480px;width:100%;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.4)}
      .top{background:${escHtml(accent)};padding:1.25rem 2rem}
      .top h1{font-size:1rem;font-weight:900;color:#1a1a1a;margin:0}
      .body{padding:2rem}
      .body h2{margin-bottom:1rem;font-size:1.3rem}
      .body p{line-height:1.7;color:#ccc}
      .body strong{color:#fff}
    </style>
  </head><body>
    <div class="card">
      <div class="top"><h1>${escHtml(siteName)}</h1></div>
      <div class="body"><h2>${escHtml(msg.title)}</h2>${msg.body}</div>
    </div>
  </body></html>`;
}

// ── Innsjekk via deltaker-PIN ───────────────────────────────────
app.post("/api/events/:id/checkin-by-pin", rateLimit(30, 60000), function(req, res) {
  const pin = (req.body.pin || "").trim();
  if (!pin) return res.status(400).json({ error: "PIN er påkrevd" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Event ikke funnet" });
  const reg = (ev.registrations || []).find(function(r) { return r.checkinPin === pin && !r.anonymized; });
  if (!reg) return res.status(404).json({ error: "Ugyldig PIN" });
  if (reg.checkedIn) return res.json({ ok: true, alreadyCheckedIn: true, name: reg.name });
  reg.checkedIn = true;
  reg.checkedInAt = new Date().toISOString();
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true, alreadyCheckedIn: false, name: reg.name });
});

// ── E-postmaler per avdeling / undergruppe ─────────────────────
app.get("/api/departments/:id/email-templates", auth, function(req, res) {
  const s = getSettings();
  const dept = (s.departments || []).find(function(d) { return d.id === req.params.id; });
  if (!dept) return res.status(404).json({ error: "Avdeling ikke funnet" });
  res.json(dept.emailTemplates || {});
});

app.put("/api/departments/:id/email-templates", auth, function(req, res) {
  const me = req.session.user;
  const s  = getSettings();
  const idx = (s.departments || []).findIndex(function(d) { return d.id === req.params.id; });
  if (idx === -1) return res.status(404).json({ error: "Avdeling ikke funnet" });
  if (me.role !== "admin") {
    var myAccess = getAccessList(readJSON(USERS_FILE).find(function(u) { return u.id === me.id; }) || {});
    var ok = myAccess.some(function(t) { return t.department === req.params.id && (t.role === "department_manager" || t.role === "avdelingsleder"); });
    if (!ok) return res.status(403).json({ error: "Ingen tilgang" });
  }
  if (!s.departments[idx].emailTemplates) s.departments[idx].emailTemplates = {};
  ["registration","cancellation","interest","lottery","newUser","passwordReset"].forEach(function(k) {
    if (req.body[k] !== undefined) s.departments[idx].emailTemplates[k] = req.body[k];
  });
  saveSettings(s);
  res.json(s.departments[idx].emailTemplates);
});

app.get("/api/departments/:deptId/subgroups/:sgId/email-templates", auth, function(req, res) {
  const s    = getSettings();
  const dept = (s.departments || []).find(function(d) { return d.id === req.params.deptId; });
  if (!dept) return res.status(404).json({ error: "Avdeling ikke funnet" });
  const sg = (dept.subgroups || []).find(function(x) { return x.id === req.params.sgId; });
  if (!sg) return res.status(404).json({ error: "Undergruppe ikke funnet" });
  res.json(sg.emailTemplates || {});
});

app.put("/api/departments/:deptId/subgroups/:sgId/email-templates", auth, function(req, res) {
  const me  = req.session.user;
  const s   = getSettings();
  const dept = (s.departments || []).find(function(d) { return d.id === req.params.deptId; });
  if (!dept) return res.status(404).json({ error: "Avdeling ikke funnet" });
  const sgIdx = (dept.subgroups || []).findIndex(function(x) { return x.id === req.params.sgId; });
  if (sgIdx === -1) return res.status(404).json({ error: "Undergruppe ikke funnet" });
  if (me.role !== "admin") {
    var a = getAccessList(readJSON(USERS_FILE).find(function(u) { return u.id === me.id; }) || {});
    var ok2 = a.some(function(t) {
      if (t.department !== req.params.deptId) return false;
      if (t.role === "department_manager" || t.role === "avdelingsleder") return true;
      return (t.role === "subgroup_manager" || t.role === "undergruppeansvarlig") && (t.subgroups || []).indexOf(req.params.sgId) !== -1;
    });
    if (!ok2) return res.status(403).json({ error: "Ingen tilgang" });
  }
  if (!dept.subgroups[sgIdx].emailTemplates) dept.subgroups[sgIdx].emailTemplates = {};
  ["registration","cancellation","interest","lottery","newUser","passwordReset"].forEach(function(k) {
    if (req.body[k] !== undefined) dept.subgroups[sgIdx].emailTemplates[k] = req.body[k];
  });
  saveSettings(s);
  res.json(dept.subgroups[sgIdx].emailTemplates);
});

app.delete("/api/events/:id/registrations/:rid", auth, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const reg = (ev.registrations || []).find(function(r) { return r.id === req.params.rid; });
  ev.registrations = ev.registrations.filter(function(r) { return r.id !== req.params.rid; });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  // Send avmeldingsbekreftelse hvis e-post er aktivert
  if (reg && reg.email && !reg.anonymized) {
    const mail = emailCancellationConfirmation(ev, reg, getSettings());
    sendEmail({ to: reg.email, subject: mail.subject, html: mail.html, text: mail.text }).catch(() => {});
  }
  res.json({ ok: true });
});

// Deltaker krysser av selv (kurs)
app.post("/api/events/:id/registrations/:rid/checkin", rateLimit(30, 60000), function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const r = (ev.registrations || []).find(function(r) { return r.id === req.params.rid; });
  if (!r) return res.status(404).json({ error: "Ikke funnet" });
  r.checkedIn   = true;
  r.checkedInAt = new Date().toISOString();
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

// ── Staff PIN verify ─────────────────────────────────────────────
app.post("/api/events/:id/staff/verify-pin", rateLimit(20, 60000), function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.staffPin) return res.json({ ok: true }); // No PIN set – always allow
  if (req.body.pin === ev.staffPin) return res.json({ ok: true });
  res.status(403).json({ error: "Feil PIN" });
});

// ── Staff API ────────────────────────────────────────────────────
app.get("/api/events/:id/staff", auth, function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  res.json(ev.staff || []);
});

app.post("/api/events/:id/staff", rateLimit(20, 60000), auth, managerOrAdmin, function(req, res) {
  const name  = req.body.name;
  const role  = req.body.role || "";
  const email = (req.body.email || "").trim().toLowerCase();
  if (!name) return res.status(400).json({ error: "Navn er påkrevd" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.staff) ev.staff = [];

  // Prevent duplicate staff (same email or same name)
  if (email && ev.staff.find(function(s) { return s.email && s.email.toLowerCase() === email; }))
    return res.status(400).json({ error: "Denne personen er allerede lagt til som personal" });
  if (!email && ev.staff.find(function(s) { return s.name.toLowerCase() === name.toLowerCase(); }))
    return res.status(400).json({ error: "En person med dette navnet er allerede lagt til" });

  // Auto-add to volunteers if not already there
  const volunteers = readJSON(VOLUNTEERS_FILE) || [];
  const alreadyVol = volunteers.find(function(v) {
    return (email && v.email && v.email.toLowerCase() === email) ||
           v.name.toLowerCase() === name.toLowerCase();
  });
  let volId = alreadyVol ? alreadyVol.id : null;
  if (!alreadyVol) {
    const newVol = { id: uuid(), name: name, email: email || "", phone: "", department: ev.department || "", events: [], createdAt: new Date().toISOString(), autoAdded: true };
    volunteers.push(newVol);
    volId = newVol.id;
    writeJSON(VOLUNTEERS_FILE, volunteers);
  }

  const staffEntry = { id: uuid(), name: name, role: role, checkedIn: false, addedAt: new Date().toISOString() };
  if (email) staffEntry.email = email;
  if (volId) staffEntry.volunteerId = volId;
  ev.staff.push(staffEntry);
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

app.delete("/api/events/:id/staff/:sid", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.staff) ev.staff = [];
  ev.staff = ev.staff.filter(function(s) { return s.id !== req.params.sid; });
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

// ── Shifts (tidslukker) ───────────────────────────────────────────
app.get("/api/events/:id/shifts", auth, function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  res.json(ev.shifts || []);
});

app.post("/api/events/:id/shifts", auth, managerOrAdmin, function(req, res) {
  const { staffIds, staffId, date, startTime, endTime } = req.body;
  const ids = Array.isArray(staffIds) ? staffIds : (staffId ? [staffId] : []);
  if (!ids.length || !date || !startTime || !endTime)
    return res.status(400).json({ error: "staffIds, date, startTime and endTime are required" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.shifts) ev.shifts = [];
  ev.shifts.push({ id: uuid(), staffIds: ids, date, startTime, endTime });
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

app.put("/api/events/:id/shifts/:shid", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const sh = (ev.shifts || []).find(function(s) { return s.id === req.params.shid; });
  if (!sh) return res.status(404).json({ error: "Tidsluke ikke funnet" });
  if (req.body.staffIds !== undefined) sh.staffIds = req.body.staffIds;
  if (req.body.startTime) sh.startTime = req.body.startTime;
  if (req.body.endTime)   sh.endTime   = req.body.endTime;
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

app.delete("/api/events/:id/shifts/:shid", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  ev.shifts = (ev.shifts || []).filter(function(s) { return s.id !== req.params.shid; });
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

app.post("/api/events/:id/staff/checkin", rateLimit(30, 60000), function(req, res) {
  const name       = req.body.name;
  const role       = req.body.role || "";
  const department = req.body.department || "";
  const staffId    = req.body.staffId;
  const events     = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.staff) ev.staff = [];
  if (staffId) {
    const s = ev.staff.find(function(s) { return s.id === staffId; });
    if (!s) return res.status(404).json({ error: "Ikke funnet" });
    s.checkedIn   = true;
    s.checkedInAt = new Date().toISOString();
    writeJSON(EVENTS_FILE, events);
    res.json({ ok: true, id: staffId });
  } else {
    if (!name) return res.status(400).json({ error: "Navn er påkrevd" });
    const newId = uuid();
    const entry = { id: newId, name: name, role: role, checkedIn: true, addedAt: new Date().toISOString(), checkedInAt: new Date().toISOString() };
    if (department) entry.department = department;
    ev.staff.push(entry);
    writeJSON(EVENTS_FILE, events);
    res.json({ ok: true, id: newId });
  }
});

// ── Samarbeid (collaborators) ────────────────────────────────────

// Helper: check if user belongs to a department (owner or guest)
function getUserDepartments(user) {
  if (user.role === "admin") {
    return (getSettings().departments || []).map(function(a) { return a.id; });
  }
  return getAccessList(user).map(function(t) { return t.department; }).filter(Boolean);
}

// Send invitation to another department
app.post("/api/events/:id/collaborators", auth, managerOrAdmin, function(req, res) {
  const departmentId = req.body.departmentId;
  if (!departmentId) return res.status(400).json({ error: "departmentId is required" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!canEditEvent(ev, req.session.user))
    return res.status(403).json({ error: "Ingen tilgang" });
  if (ev.department === departmentId)
    return res.status(400).json({ error: "Kan ikke invitere egen avdeling" });
  if (!ev.collaborators) ev.collaborators = [];
  if (ev.collaborators.find(function(c) { return c.departmentId === departmentId; }))
    return res.status(400).json({ error: "Allerede invitert" });
  ev.collaborators.push({ departmentId, status: "pending", invitedAt: new Date().toISOString() });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

// Svar på invitasjon (accept/decline)
app.put("/api/events/:id/collaborators/:deptId", auth, managerOrAdmin, function(req, res) {
  const status = req.body.status; // "accepted" | "declined"
  if (!["accepted","declined"].includes(status))
    return res.status(400).json({ error: "Ugyldig status" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  // Kun leder/admin for den inviterte avdelingen kan svare
  const myAvds = getUserDepartments(req.session.user);
  if (!myAvds.includes(req.params.deptId) && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Ingen tilgang" });
  const collab = (ev.collaborators || []).find(function(c) { return c.departmentId === req.params.deptId; });
  if (!collab) return res.status(404).json({ error: "Invitasjon ikke funnet" });
  collab.status = status;
  collab.respondedAt = new Date().toISOString();
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

// Fjern collaborator (eier eller admin)
app.delete("/api/events/:id/collaborators/:deptId", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!canEditEvent(ev, req.session.user) && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Ingen tilgang" });
  ev.collaborators = (ev.collaborators || []).filter(function(c) { return c.departmentId !== req.params.deptId; });
  // Fjern også guestStaff og guestShifts for denne avdelingen
  if (ev.guestStaff) delete ev.guestStaff[req.params.deptId];
  if (ev.guestShifts) delete ev.guestShifts[req.params.deptId];
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

// ── Guest staff (staff for samarbeidsavdeling) ────────────────────
app.get("/api/events/:id/gueststaff/:deptId", auth, function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  res.json((ev.guestStaff && ev.guestStaff[req.params.deptId]) || []);
});

app.post("/api/events/:id/gueststaff/:deptId", auth, managerOrAdmin, function(req, res) {
  const name = req.body.name, role = req.body.role || "";
  if (!name) return res.status(400).json({ error: "Navn er påkrevd" });
  const myAvds = getUserDepartments(req.session.user);
  if (!myAvds.includes(req.params.deptId) && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Ingen tilgang til denne avdelingen" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const accepted = (ev.collaborators || []).find(function(c) { return c.departmentId === req.params.deptId && c.status === "accepted"; });
  if (!accepted && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Samarbeid ikke akseptert" });
  if (!ev.guestStaff) ev.guestStaff = {};
  if (!ev.guestStaff[req.params.deptId]) ev.guestStaff[req.params.deptId] = [];
  ev.guestStaff[req.params.deptId].push({ id: uuid(), name, role, checkedIn: false, addedAt: new Date().toISOString() });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

app.delete("/api/events/:id/gueststaff/:deptId/:sid", auth, managerOrAdmin, function(req, res) {
  const myAvds = getUserDepartments(req.session.user);
  if (!myAvds.includes(req.params.deptId) && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Ingen tilgang" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev || !ev.guestStaff || !ev.guestStaff[req.params.deptId])
    return res.status(404).json({ error: "Ikke funnet" });
  ev.guestStaff[req.params.deptId] = ev.guestStaff[req.params.deptId].filter(function(s) { return s.id !== req.params.sid; });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

// ── Guest shifts ──────────────────────────────────────────────────
app.get("/api/events/:id/guestshifts/:deptId", auth, function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  res.json((ev.guestShifts && ev.guestShifts[req.params.deptId]) || []);
});

app.post("/api/events/:id/guestshifts/:deptId", auth, managerOrAdmin, function(req, res) {
  const { staffIds, date, startTime, endTime } = req.body;
  const ids = Array.isArray(staffIds) ? staffIds : [];
  if (!ids.length || !date || !startTime || !endTime)
    return res.status(400).json({ error: "staffIds, date, startTime and endTime are required" });
  const myAvds = getUserDepartments(req.session.user);
  if (!myAvds.includes(req.params.deptId) && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Ingen tilgang" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.guestShifts) ev.guestShifts = {};
  if (!ev.guestShifts[req.params.deptId]) ev.guestShifts[req.params.deptId] = [];
  ev.guestShifts[req.params.deptId].push({ id: uuid(), staffIds: ids, date, startTime, endTime });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

app.put("/api/events/:id/guestshifts/:deptId/:shid", auth, managerOrAdmin, function(req, res) {
  const myAvds = getUserDepartments(req.session.user);
  if (!myAvds.includes(req.params.deptId) && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Ingen tilgang" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev || !ev.guestShifts || !ev.guestShifts[req.params.deptId])
    return res.status(404).json({ error: "Ikke funnet" });
  const sh = ev.guestShifts[req.params.deptId].find(function(s) { return s.id === req.params.shid; });
  if (!sh) return res.status(404).json({ error: "Tidsluke ikke funnet" });
  if (req.body.staffIds !== undefined) sh.staffIds = req.body.staffIds;
  if (req.body.startTime) sh.startTime = req.body.startTime;
  if (req.body.endTime)   sh.endTime   = req.body.endTime;
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

app.delete("/api/events/:id/guestshifts/:deptId/:shid", auth, managerOrAdmin, function(req, res) {
  const myAvds = getUserDepartments(req.session.user);
  if (!myAvds.includes(req.params.deptId) && req.session.user.role !== "admin")
    return res.status(403).json({ error: "Ingen tilgang" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev || !ev.guestShifts || !ev.guestShifts[req.params.deptId])
    return res.status(404).json({ error: "Ikke funnet" });
  ev.guestShifts[req.params.deptId] = ev.guestShifts[req.params.deptId].filter(function(s) { return s.id !== req.params.shid; });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

// ── Guestbook API ────────────────────────────────────────────────
app.post("/api/events/:id/guestbook", rateLimit(5, 60000), function(req, res) {
  const name    = (req.body.name || "").trim().slice(0, 100);
  const message = (req.body.message || "").trim().slice(0, 1000);
  if (!name || !message) return res.status(400).json({ error: "Navn og melding er påkrevd" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.guestbook) ev.guestbook = [];
  const gbId = uuid();
  ev.guestbook.push({ id: gbId, name: name, message: message, approved: false, createdAt: new Date().toISOString() });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true, id: gbId });
});

// ── Gjestebok bilde-opplasting via QR ───────────────────────────
// In-memory token store: token -> { evId, gbId, expires, photoUrl }
const _gbPhotoTokens = new Map();
const _gbPhotoSSE    = new Map(); // token -> res

// Opprett token for bildeupplasting
app.post("/api/events/:id/guestbook/:gid/photo-token", rateLimit(10, 60000), function(req, res) {
  const evId = req.params.id;
  const gbId = req.params.gid;
  const ev   = readJSON(EVENTS_FILE).find(function(e) { return e.id === evId || e.slug === evId; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const entry = (ev.guestbook || []).find(function(g) { return g.id === gbId; });
  if (!entry) return res.status(404).json({ error: "Ikke funnet" });
  const token   = require("crypto").randomBytes(16).toString("hex");
  const expires = Date.now() + 10 * 60 * 1000; // 10 min
  _gbPhotoTokens.set(token, { evId: ev.id, gbId, expires });
  res.json({ token, url: "/gb-photo/" + token });
});

// SSE – vent på bilde (brukes av QR-modal på event-siden)
app.get("/api/gb-photo-wait/:token", function(req, res) {
  const token = req.params.token;
  if (!_gbPhotoTokens.has(token)) return res.status(404).json({ error: "Ugyldig token" });
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
  _gbPhotoSSE.set(token, res);
  req.on("close", function() { _gbPhotoSSE.delete(token); });
});

// Mobilside for bildevalg
app.get("/gb-photo/:token", function(req, res) {
  const token = req.params.token;
  const info  = _gbPhotoTokens.get(token);
  if (!info || Date.now() > info.expires) {
    return res.send('<!DOCTYPE html><html><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Utløpt</title><style>body{font-family:sans-serif;background:#1a1a1a;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:2rem}</style></head><body><h2>⏰ Lenken er utløpt</h2><p>Gå tilbake til event-siden og prøv igjen.</p></body></html>');
  }
  const s = getSettings();
  const siteName  = s.siteName || "Events Admin";
  const logoUrl   = s.logoUrl  || "";
  const accentCol = (s.colors && s.colors.accent) || "#FFD100";
  const logoHtml  = logoUrl
    ? `<img src="${escHtml(logoUrl)}" alt="${escHtml(siteName)}" style="height:40px;object-fit:contain;margin-bottom:1.5rem"/>`
    : `<div style="background:${escHtml(accentCol)};color:#111;font-weight:900;font-size:1.2rem;padding:5px 16px;border-radius:6px;margin-bottom:1.5rem;display:inline-block">${escHtml(siteName.split(" ")[0])}</div>`;

  res.send(`<!DOCTYPE html>
<html lang="no">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Last opp bilder – ${escHtml(siteName)}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Helvetica Neue",Arial,sans-serif;background:#1a1a1a;color:#fff;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:2rem 1.25rem;text-align:center}
h1{font-size:1.25rem;margin-bottom:.4rem}
.sub{color:#888;font-size:.88rem;margin-bottom:1.75rem;line-height:1.5}
.pick-zone{border:2px dashed #444;border-radius:12px;padding:2rem 1rem;cursor:pointer;width:100%;max-width:420px;margin-bottom:1.25rem;transition:border-color .2s}
.pick-zone:hover,.pick-zone:active{border-color:${escHtml(accentCol)}}
.pick-icon{font-size:2.5rem;margin-bottom:.5rem}
.pick-label{font-size:.95rem;color:#888}
.thumb-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem;width:100%;max-width:420px;margin-bottom:1.25rem}
.thumb-wrap{position:relative;aspect-ratio:1;border-radius:8px;overflow:hidden;background:#2a2a2a}
.thumb-wrap img{width:100%;height:100%;object-fit:cover}
.thumb-del{position:absolute;top:4px;right:4px;background:rgba(0,0,0,.7);border:none;color:#fff;border-radius:50%;width:22px;height:22px;font-size:.75rem;cursor:pointer;display:flex;align-items:center;justify-content:center;line-height:1}
.thumb-status{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:1.4rem;background:rgba(0,0,0,.45)}
.btn{background:${escHtml(accentCol)};color:#111;font-weight:700;padding:.9rem 1.5rem;border-radius:8px;font-size:1rem;border:none;cursor:pointer;width:100%;max-width:420px;margin-bottom:.75rem}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn.secondary{background:#2a2a2a;color:#fff;border:1px solid #444}
.status{font-size:.9rem;min-height:1.4rem;margin-bottom:.5rem;max-width:420px}
.ok{color:#4ade80}.err{color:#f87171}
input[type=file]{display:none}
</style>
</head>
<body>
${logoHtml}
<h1>📸 Legg ved bilder</h1>
<p class="sub">Velg ett eller flere bilder fra kamera eller galleri.<br>De knyttes til kommentaren din i gjesteboken.</p>

<div class="pick-zone" id="pickZone" onclick="document.getElementById('fileInput').click()">
  <div class="pick-icon">🖼️</div>
  <div class="pick-label">Trykk for å velge bilder</div>
</div>

<!-- Ingen capture-attributt = brukeren velger selv kamera eller galleri -->
<input type="file" id="fileInput" accept="image/*" multiple onchange="onFilesChange(this)"/>

<div class="thumb-grid" id="thumbGrid" style="display:none"></div>

<div class="status" id="status"></div>

<button class="btn" id="addMoreBtn" style="display:none" onclick="document.getElementById('fileInput').click()">➕ Legg til flere bilder</button>
<button class="btn" id="sendBtn" style="display:none" onclick="sendAllPhotos()">✅ Send alle bilder (<span id="sendCount">0</span>)</button>

<script>
var selectedFiles = [];
var token = "${token}";

function onFilesChange(input) {
  var files = Array.from(input.files);
  if (!files.length) return;
  files.forEach(function(f) { selectedFiles.push({ file: f, status: "pending" }); });
  input.value = "";
  renderThumbs();
}

function renderThumbs() {
  var grid = document.getElementById("thumbGrid");
  var zone = document.getElementById("pickZone");
  var sendBtn = document.getElementById("sendBtn");
  var addBtn  = document.getElementById("addMoreBtn");
  var countEl = document.getElementById("sendCount");

  if (!selectedFiles.length) {
    grid.style.display = "none";
    zone.style.display = "block";
    sendBtn.style.display = "none";
    addBtn.style.display  = "none";
    return;
  }

  zone.style.display = "none";
  grid.style.display = "grid";
  addBtn.style.display  = "block";

  var pending = selectedFiles.filter(function(f){ return f.status === "pending"; }).length;
  countEl.textContent = pending;
  sendBtn.style.display = pending > 0 ? "block" : "none";

  grid.innerHTML = "";
  selectedFiles.forEach(function(item, i) {
    var wrap = document.createElement("div");
    wrap.className = "thumb-wrap";

    var img = document.createElement("img");
    var reader = new FileReader();
    reader.onload = function(e){ img.src = e.target.result; };
    reader.readAsDataURL(item.file);
    wrap.appendChild(img);

    if (item.status === "pending") {
      var del = document.createElement("button");
      del.className = "thumb-del";
      del.textContent = "×";
      del.onclick = function(e) {
        e.stopPropagation();
        selectedFiles.splice(i, 1);
        renderThumbs();
      };
      wrap.appendChild(del);
    } else if (item.status === "done") {
      var ov = document.createElement("div");
      ov.className = "thumb-status";
      ov.textContent = "✅";
      wrap.appendChild(ov);
    } else if (item.status === "error") {
      var ov2 = document.createElement("div");
      ov2.className = "thumb-status";
      ov2.style.color = "#f87171";
      ov2.textContent = "❌";
      wrap.appendChild(ov2);
    } else if (item.status === "sending") {
      var ov3 = document.createElement("div");
      ov3.className = "thumb-status";
      ov3.textContent = "⏳";
      wrap.appendChild(ov3);
    }

    grid.appendChild(wrap);
  });
}

async function sendAllPhotos() {
  var pending = selectedFiles.filter(function(f){ return f.status === "pending"; });
  if (!pending.length) return;

  document.getElementById("sendBtn").disabled = true;
  document.getElementById("addMoreBtn").disabled = true;
  document.getElementById("status").innerHTML = "⏳ Sender " + pending.length + " bilde" + (pending.length > 1 ? "r" : "") + "…";

  var ok = 0, fail = 0;
  for (var i = 0; i < selectedFiles.length; i++) {
    if (selectedFiles[i].status !== "pending") continue;
    selectedFiles[i].status = "sending";
    renderThumbs();
    var fd = new FormData();
    fd.append("photo", selectedFiles[i].file);
    try {
      var r = await fetch("/api/gb-photo/" + token, { method: "POST", body: fd });
      var d = await r.json();
      if (r.ok) { selectedFiles[i].status = "done"; ok++; }
      else { selectedFiles[i].status = "error"; fail++; }
    } catch(e) {
      selectedFiles[i].status = "error"; fail++;
    }
    renderThumbs();
  }

  var st = document.getElementById("status");
  if (fail === 0) {
    st.innerHTML = '<span class="ok">✅ ' + ok + ' bilde' + (ok > 1 ? "r" : "") + ' sendt!</span>';
  } else {
    st.innerHTML = '<span class="ok">' + ok + ' sendt</span> · <span class="err">' + fail + ' feilet</span>';
    document.getElementById("sendBtn").disabled = false;
    document.getElementById("sendBtn").textContent = "🔄 Prøv feilede bilder";
    // Reset failed to pending so they can be retried
    selectedFiles.forEach(function(f){ if(f.status === "error") f.status = "pending"; });
    renderThumbs();
  }
  document.getElementById("addMoreBtn").disabled = false;
}
</script>
</body>
</html>`);
});

// Motta bilde fra mobil
const photoUpload = multer({
  storage: multer.diskStorage({
    destination: function(req, file, cb) {
      const dir = path.join(DATA, "gb-photos");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: function(req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
      cb(null, req.params.token + "_" + Date.now() + ext);
    }
  }),
  fileFilter: function(req, file, cb) { cb(null, /^image\//.test(file.mimetype)); },
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.post("/api/gb-photo/:token", rateLimit(20, 60000), photoUpload.single("photo"), function(req, res) {
  const token = req.params.token;
  const info  = _gbPhotoTokens.get(token);
  if (!info || Date.now() > info.expires) return res.status(410).json({ error: "Token utløpt" });
  if (!req.file) return res.status(400).json({ error: "Ingen fil" });

  const photoUrl = "/gb-photos/" + req.file.filename;

  // Knytt bilde til gjestebok-oppføring
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === info.evId; });
  if (ev) {
    const entry = (ev.guestbook || []).find(function(g) { return g.id === info.gbId; });
    if (entry) {
      entry.photos = entry.photos || [];
      entry.photos.push(photoUrl);
      writeJSON(EVENTS_FILE, events);
    }
  }

  // Varsle SSE-klient om hvert bilde (ikke slett SSE, kan komme flere)
  const sseRes = _gbPhotoSSE.get(token);
  if (sseRes) {
    sseRes.write("data: " + JSON.stringify({ ok: true, photoUrl, count: (ev && ev.guestbook && ev.guestbook.find(function(g){return g.id===info.gbId;})) ? ((ev.guestbook.find(function(g){return g.id===info.gbId;})).photos||[]).length : 1 }) + "\n\n");
  }

  // Token lever videre – slettes ikke etter første bilde
  // Utløper automatisk etter 10 min (sjekkes ved neste request)
  res.json({ ok: true, photoUrl });
});

// Serve gjestebok-bilder
app.use("/gb-photos", express.static(path.join(DATA, "gb-photos")));

app.get("/api/events/:id/guestbook", auth, function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  res.json(ev.guestbook || []);
});

app.put("/api/events/:id/guestbook/:gid/approve", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const g = ev.guestbook.find(function(g) { return g.id === req.params.gid; });
  if (!g) return res.status(404).json({ error: "Ikke funnet" });
  g.approved = true;
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

app.delete("/api/events/:id/guestbook/:gid", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (!ev.guestbook) ev.guestbook = [];
  ev.guestbook = ev.guestbook.filter(function(g) { return g.id !== req.params.gid; });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

// ── Serie API ────────────────────────────────────────────────────
// Repeat-typer:
//   yearly-date     - hvert ar, samme dag+maned (f.eks. 17. mai)
//   yearly-nodate   - hvert ar, ingen fast dato (f.eks. "MC-treff mai")
//   weekly          - hver uke, samme ukedag
//   monthly-date    - hver maned, samme dato (f.eks. alltid den 15.)
//   monthly-weekday - hver maned, samme ukedag-nr (f.eks. forste tirsdag)

function nextSeriesDate(seriesEntry, fromDate) {
  var d = new Date(fromDate);
  var repeat = seriesEntry.repeat;
  if (repeat === "yearly-date") {
    d.setFullYear(d.getFullYear() + 1);
  } else if (repeat === "yearly-nodate") {
    return null;
  } else if (repeat === "weekly") {
    d.setDate(d.getDate() + 7);
  } else if (repeat === "monthly-date") {
    d.setMonth(d.getMonth() + 1);
  } else if (repeat === "monthly-weekday") {
    var weekday = d.getDay();
    var weekNum = Math.ceil(d.getDate() / 7);
    var origMonth = d.getMonth();
    d.setMonth(d.getMonth() + 1);
    d.setDate(1);
    var firstWd = d.getDay();
    var diff = (weekday - firstWd + 7) % 7;
    d.setDate(1 + diff + (weekNum - 1) * 7);
    if (d.getMonth() !== (origMonth + 1) % 12) { d.setDate(d.getDate() - 7); }
  } else {
    return null;
  }
  return d;
}

app.get("/api/series", auth, function(req, res) {
  var series = readJSON(SERIES_F);
  if (!Array.isArray(series)) series = [];
  var events = readJSON(EVENTS_FILE);
  series = series.map(function(s) {
    var evs = events.filter(function(e) { return e.seriesId === s.id && e.date; });
    evs.sort(function(a,b) { return new Date(b.date) - new Date(a.date); });
    var lastDate = evs.length ? evs[0].date : null;
    var next = (lastDate && s.repeat !== "yearly-nodate") ? nextSeriesDate(s, lastDate) : null;
    return Object.assign({}, s, {
      eventCount: events.filter(function(e){return e.seriesId===s.id;}).length,
      lastDate: lastDate,
      nextSuggested: next ? next.toISOString().slice(0,16) : null
    });
  });
  res.json(series);
});

app.post("/api/series", auth, managerOrAdmin, function(req, res) {
  var series = readJSON(SERIES_F);
  if (!Array.isArray(series)) series = [];
  var s = {
    id: uuid(),
    name: (req.body.name || "").trim().slice(0, 200),
    repeat: req.body.repeat || "yearly-nodate",
    department: req.body.department || null,
    subgroup: req.body.subgroup || null,
    sharedGuestbook: true,
    createdAt: new Date().toISOString(),
    createdBy: req.session.user.email,
  };
  if (!s.name) return res.status(400).json({ error: "Navn er påkrevd" });
  series.push(s);
  fs.writeFileSync(SERIES_F, JSON.stringify(series, null, 2));
  res.json(s);
});

app.put("/api/series/:id", auth, managerOrAdmin, function(req, res) {
  var series = readJSON(SERIES_F);
  var i = series.findIndex(function(s) { return s.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  if (req.body.name        !== undefined) series[i].name        = (req.body.name || "").trim().slice(0, 200);
  if (req.body.repeat      !== undefined) series[i].repeat      = req.body.repeat;
  if (req.body.department    !== undefined) series[i].department    = req.body.department || null;
  if (req.body.subgroup !== undefined) series[i].subgroup = req.body.subgroup || null;
  fs.writeFileSync(SERIES_F, JSON.stringify(series, null, 2));
  res.json({ ok: true });
});

app.delete("/api/series/:id", auth, managerOrAdmin, function(req, res) {
  var series = readJSON(SERIES_F);
  fs.writeFileSync(SERIES_F, JSON.stringify(series.filter(function(s){ return s.id !== req.params.id; }), null, 2));
  var events = readJSON(EVENTS_FILE);
  events.forEach(function(e) { if (e.seriesId === req.params.id) delete e.seriesId; });
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

app.get("/api/series/:id/guestbook", function(req, res) {
  var series = readJSON(SERIES_F);
  var seriesEntry = series.find(function(s) { return s.id === req.params.id; });
  if (!seriesEntry) return res.status(404).json({ error: "Ikke funnet" });
  var events = readJSON(EVENTS_FILE);
  var all = [];
  events.filter(function(e) { return e.seriesId === req.params.id; }).forEach(function(e) {
    (e.guestbook || []).forEach(function(g) {
      all.push(Object.assign({}, g, { eventTitle: e.title, eventDate: e.date, eventId: e.id }));
    });
  });
  all.sort(function(a,b) { return new Date(b.createdAt) - new Date(a.createdAt); });
  res.json(all);
});

// ── Blokker API ─────────────────────────────────────────────────
// Data model: { id, department, name, eventType (mote/stand/kurs/tur/any),
//               dateFrom, dateTo, ansvarligId, note, createdBy }

function readBlocks() {
  try { return JSON.parse(fs.readFileSync(BLOCKS_F)); } catch(e) { return []; }
}

// GET /api/blocks?department=id  – all in the department see the blocks
app.get("/api/blocks", auth, function(req, res) {
  var blocks = readBlocks();
  var me = req.session.user;
  var deptId = req.query.department || null;
  if (me.role === "admin") {
    return res.json(deptId ? blocks.filter(function(b){ return b.department === deptId; }) : blocks);
  }
  // Avdeling og medlem ser kun sin avdelings blokker
  var myDeptIds = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
  res.json(blocks.filter(function(b){ return myDeptIds.indexOf(b.department) !== -1; }));
});

// VIKTIG: /check må stå FØR /:id, ellers tolker Express "check" som en :id
app.get("/api/blocks/check", auth, function(req, res) {
  var date   = req.query.date;
  var deptId  = req.query.department;
  var evType = req.query.eventType || "stand";
  if (!date || !deptId) return res.json({ conflict: false });
  var blocks = readBlocks();
  var d = new Date(date);
  var hits = blocks.filter(function(b) {
    if (b.department !== deptId) return false;
    if (b.eventType !== "any" && b.eventType !== evType) return false;
    return d >= new Date(b.dateFrom) && d <= new Date(b.dateTo);
  });
  res.json({ conflict: hits.length > 0, blocks: hits });
});

app.post("/api/blocks", auth, managerOrAdmin, function(req, res) {
  var me = req.session.user;
  var meAvdeling = me.department || (getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {})[0] || {}).department || null;
  var blocks = readBlocks();
  var b = {
    id:          uuid(),
    department:    req.body.department || meAvdeling,
    name:        (req.body.name || "").trim().slice(0, 200),
    eventType:   req.body.eventType || "any",
    dateFrom:    req.body.dateFrom || null,
    dateTo:      req.body.dateTo   || null,
    ansvarligId: req.body.ansvarligId || null,
    note:        req.body.note || "",
    createdBy:   me.email,
    createdAt:   new Date().toISOString(),
  };
  if (!b.name || !b.dateFrom || !b.dateTo)
    return res.status(400).json({ error: "Navn, startdato og sluttdato er påkrevd" });
  blocks.push(b);
  fs.writeFileSync(BLOCKS_F, JSON.stringify(blocks, null, 2));
  res.json(b);
});

app.put("/api/blocks/:id", auth, managerOrAdmin, function(req, res) {
  var blocks = readBlocks();
  var i = blocks.findIndex(function(b){ return b.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  ["name","eventType","dateFrom","dateTo","ansvarligId","note","department"].forEach(function(k){
    if (req.body[k] !== undefined) blocks[i][k] = req.body[k];
  });
  fs.writeFileSync(BLOCKS_F, JSON.stringify(blocks, null, 2));
  res.json({ ok: true });
});

app.delete("/api/blocks/:id", auth, managerOrAdmin, function(req, res) {
  var blocks = readBlocks();
  fs.writeFileSync(BLOCKS_F, JSON.stringify(blocks.filter(function(b){ return b.id !== req.params.id; }), null, 2));
  res.json({ ok: true });
});

// ── GDPR: Anonymiser gamle påmeldinger ──────────────────────────
// Leser retentionDays fra settings.json (kan overstyres av env-variabel)
function getRetentionDays() {
  if (process.env.GDPR_RETENTION_DAYS) return Number(process.env.GDPR_RETENTION_DAYS);
  return getSettings().gdprRetentionDays || 365;
}

function anonymizeOldRegistrations() {
  const retentionDays = getRetentionDays();
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  const events = readJSON(EVENTS_FILE);
  let count = 0;
  events.forEach(function(ev) {
    (ev.registrations || []).forEach(function(r) {
      if (r.anonymized) return;
      const regDate = new Date(r.registeredAt).getTime();
      const evDate  = ev.date ? new Date(ev.date).getTime() : regDate;
      // Anonymiser hvis BÅDE registreringsdato og eventdato er eldre enn cutoff
      if (regDate < cutoff && evDate < cutoff) {
        r.name        = "[slettet]";
        r.email       = "[slettet]";
        r.phone       = "";
        r.checkinPin  = null;
        r.cancelToken = null;
        r.vehicle     = null;
        r.emergency   = null;
        r.anonymized  = true;
        r.anonymizedAt = new Date().toISOString();
        count++;
      }
    });
  });
  if (count > 0) {
    writeJSON(EVENTS_FILE, events);
    console.log("GDPR: anonymized " + count + " old registrations (retention: " + retentionDays + " days)");
  }
  return count;
}

// Kjør ved oppstart og deretter én gang per dag
anonymizeOldRegistrations();
setInterval(anonymizeOldRegistrations, 24 * 60 * 60 * 1000);

// Manuell trigger for admin
app.post("/api/admin/gdpr/anonymize", auth, adminOnly, function(req, res) {
  const count = anonymizeOldRegistrations();
  res.json({ ok: true, anonymized: count, retentionDays: getRetentionDays() });
});

app.get("/api/admin/gdpr/status", auth, adminOnly, function(req, res) {
  const retentionDays = getRetentionDays();
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  const events = readJSON(EVENTS_FILE);
  let pending = 0, anonymized = 0;
  events.forEach(function(ev) {
    (ev.registrations || []).forEach(function(r) {
      if (r.anonymized) { anonymized++; return; }
      const regDate = new Date(r.registeredAt).getTime();
      const evDate  = ev.date ? new Date(ev.date).getTime() : regDate;
      if (regDate < cutoff && evDate < cutoff) pending++;
    });
  });
  res.json({ retentionDays, pending, anonymized });
});

// ── E-post test-sending (admin) ──────────────────────────────────
app.post("/api/admin/email/test", auth, adminOnly, async function(req, res) {
  const s = getSettings();
  if (!s.emailEnabled) return res.status(400).json({ error: "E-post er ikke aktivert i innstillinger" });
  const transport = getTransporter();
  if (!transport) return res.status(400).json({ error: "SMTP er ikke konfigurert – sjekk SMTP_HOST/USER/PASS" });
  const to = req.body.to || req.session.user.email;
  const r = await sendEmail({
    to,
    subject: "✅ Test – " + (s.siteName || "Events Admin"),
    html: `<div style="font-family:sans-serif;padding:2rem"><h2>E-postutsending fungerer! 🎉</h2><p>Denne testen ble sendt fra <strong>${s.siteName || "Events Admin"}</strong>.</p><p style="color:#999;font-size:.85rem">Avsender: ${s.emailFrom || "noreply@" + s.eventDomain}</p></div>`,
    text: "E-postutsending fungerer! Sendt fra " + (s.siteName || "Events Admin"),
  });
  if (!r.ok) return res.status(500).json({ error: r.reason });
  res.json({ ok: true, to, id: r.id });
});
app.get("/api/stats", auth, function(req, res) {
  const events   = readJSON(EVENTS_FILE);
  const now      = Date.now();
  const yearStart = new Date(new Date().getFullYear(), 0, 1).getTime();
  const monthStart= new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime();
  const sorted   = events.slice().sort(function(a,b){ return new Date(b.date)-new Date(a.date); });

  // Volunteer stats
  const volunteerMap = new Map();
  events.forEach(function(ev) {
    if (!ev.date || new Date(ev.date).getTime() < yearStart) return;
    (ev.staff || []).forEach(function(s) {
      if (s.checkedIn && s.name && s.name !== "[slettet]") {
        const key = s.name.trim().toLowerCase();
        volunteerMap.set(key, (volunteerMap.get(key) || 0) + 1);
      }
    });
  });
  const totalAppearances = Array.from(volunteerMap.values()).reduce(function(s,n){ return s+n; }, 0);

  // Event counts by type
  const evByType = { mote:0, stand:0, kurs:0, tur:0 };
  events.forEach(function(ev){ const t=ev.eventType||"stand"; if(evByType[t]!==undefined) evByType[t]++; });

  // This year / this month
  const evThisYear  = events.filter(function(e){ return e.date && new Date(e.date).getTime() >= yearStart; });
  const evThisMonth = events.filter(function(e){ return e.date && new Date(e.date).getTime() >= monthStart; });

  // Upcoming events
  const upcoming = events.filter(function(e){ return e.date && new Date(e.date).getTime() > now; });
  upcoming.sort(function(a,b){ return new Date(a.date)-new Date(b.date); });

  // Registration stats
  const totalRegs   = events.reduce(function(s,e){ return s+(e.registrations||[]).length; },0);
  const regsYear    = evThisYear.reduce(function(s,e){ return s+(e.registrations||[]).length; },0);
  const checkedIn   = events.reduce(function(s,e){ return s+(e.registrations||[]).filter(function(r){return r.checkedIn;}).length; },0);
  const checkinRate = totalRegs > 0 ? Math.round(checkedIn/totalRegs*100) : 0;
  const maxParticipants = events.filter(function(e){ return e.maxParticipants>0; });
  const avgCapacity  = maxParticipants.length
    ? Math.round(maxParticipants.reduce(function(s,e){return s+(e.registrations||[]).length/e.maxParticipants;},0)/maxParticipants.length*100)
    : null;

  // Avg regs per event
  const avgRegs = events.length ? (totalRegs / events.length).toFixed(1) : 0;

  // Guestbook entries approved
  const guestbookTotal = events.reduce(function(s,e){ return s+(e.guestbook||[]).filter(function(g){return g.approved;}).length; },0);

  // Walk-ins
  const walkIns = events.reduce(function(s,e){ return s+(e.registrations||[]).filter(function(r){return r.walkIn;}).length; },0);

  res.json({
    // Core
    totalEvents:        events.length,
    totalRegistrations: totalRegs,
    activeVolunteers:   volunteerMap.size,
    totalAppearances:   totalAppearances,
    // By type
    eventsStand:  evByType.stand,
    eventsKurs:   evByType.kurs,
    eventsTur:    evByType.tur,
    // Time-based
    eventsThisYear:  evThisYear.length,
    eventsThisMonth: evThisMonth.length,
    regsThisYear:    regsYear,
    upcomingEvents:  upcoming.length,
    // Quality
    checkedInTotal:  checkedIn,
    checkinRate:     checkinRate,
    avgRegsPerEvent: avgRegs,
    avgCapacityFill: avgCapacity,
    guestbookEntries: guestbookTotal,
    walkIns:          walkIns,
    // Recent
    recentEvents: sorted.slice(0, 5).map(function(e) {
      return {
        id: e.id, slug: e.slug, title: e.title, date: e.date,
        department: e.department || null,
        registrationCount: (e.registrations || []).length,
        maxParticipants: e.maxParticipants,
        staffCount: (e.staff || []).length,
        staffCheckedIn: (e.staff || []).filter(function(s){ return s.checkedIn; }).length,
      };
    }),
  });
});

// ── AI Proxy (Claude API) ─────────────────────────────────────────
const MOCK_AI = !process.env.ANTHROPIC_API_KEY;

app.post("/api/ai/parse-pdf", auth, managerOrAdmin, rateLimit(5, 60000), async function(req, res) {
  const { base64, fileType, department: deptFromBody, targetYear, subgroups: subgroupsFromBody } = req.body;
  if (!base64) return res.status(400).json({ error: "Mangler fil-data" });

  if (MOCK_AI) {
    // Mock uses the actual PDF content (Årshjul 2026 NAF avd. Romerike)
    const av = deptFromBody || "NAF avd. Romerike";
    const y = Number(targetYear) || new Date().getFullYear();
    const ny = y + 1;
    return res.json({ events: [
      { title:"Temakveld: fra dødsveier til nullvisjon", date:`${y}-02-12T18:00`, location:"NAF-senteret i Rælingen", description:"Temakveld med Sissel Sanderlin om trafikksikkerhet.", eventType:"kurs", department:av, subgroup:null },
      { title:"Verdiseminar for russ", date:`${y}-02-24T00:00`, location:"Thon Hotel Arena Lillestrøm", description:"Verdiseminar med Veltepetter, kollisjonsvekter og promillebriller.", eventType:"kurs", department:av, subgroup:null },
      { title:"Årsmøte NAF MC Romerike", date:`${y}-02-26T18:30`, location:"NAF-senteret i Rælingen", description:"Årsmøte for NAF MC Romerike.", eventType:"stand", department:av, subgroup:null },
      { title:"MC-messe NOVA spektrum", date:`${y}-02-27T00:00`, location:"NOVA spektrum", description:"MC-messe over to dager.", eventType:"stand", department:av, subgroup:null },
      { title:"Kickoff, frivillige", date:`${y}-03-02T17:00`, location:"NAF senter Rælingen", description:"Kickoff for frivillige, 17:00–19:00.", eventType:"stand", department:av, subgroup:null },
      { title:"Senior trafikkurs", date:`${y}-03-09T12:00`, location:"Jessheim/NAF senter Rælingen", description:"Senior trafikkurs 9. og 10. mars.", eventType:"kurs", department:av, subgroup:null },
      { title:"Klubb-kveld Bullfighter", date:`${y}-03-11T18:00`, location:"Kalbakken", description:"Klubbkveld for MC.", eventType:"stand", department:av, subgroup:null },
      { title:"Fagkveld", date:`${y}-03-16T18:00`, location:"NAF-senteret i Rælingen", description:"Fagkveld for MC-avdelingen.", eventType:"kurs", department:av, subgroup:null },
      { title:"Årsmøte NAF avd. Romerike", date:`${y}-03-19T18:00`, location:"Olavsgaard hotel", description:"Årsmøte for NAF avdeling Romerike. Gjelder både Lokalavdeling og MC.", eventType:"stand", department:av, subgroup:null },
      { title:"Påskeaksjon – Circle K Dal og Berger", date:`${y}-03-27T14:00`, location:"Circle K Dal og Berger", description:"Påskeaksjon 14:00–18:00.", eventType:"stand", department:av, subgroup:null },
      { title:"Påskeaksjon – Circle K Fetsund", date:`${y}-03-28T10:00`, location:"Circle K Fetsund", description:"Påskeaksjon 10:00–15:00.", eventType:"stand", department:av, subgroup:null },
      { title:"Senior trafikkurs", date:`${y}-04-16T00:00`, location:"Jessheim/NAF senter Rælingen", description:"Senior trafikkurs for lokalavdeling.", eventType:"kurs", department:av, subgroup:null },
      { title:"Trygg på glatta", date:`${y}-04-11T10:00`, location:"Øvingsbanen Fet", description:"Trygg på glatta-kurs. Frivillige møter 09:00.", eventType:"kurs", department:av, subgroup:null },
      { title:"Sikkerhetsdag Bjørkelangen", date:`${y}-04-25T10:00`, location:"Rådhusveien, Bjørkelangen", description:"Sikkerhetsdag med NAFFEN, Veltepetter og Bråstopp.", eventType:"kurs", department:av, subgroup:null },
      { title:"Åpen dag for alle", date:`${y}-04-27T17:30`, location:"NAF-senter i Rælingen", description:"Åpen dag for MC-interesserte.", eventType:"stand", department:av, subgroup:null },
      { title:"Nebbenes kro", date:`${y}-05-01T09:00`, location:"Eidsvoll verk", description:"MC-tur til Nebbenes kro.", eventType:"tur", department:av, subgroup:null },
      { title:"Se oss-aksjon m. NMCU", date:`${y}-05-01T10:00`, location:"Esso Gardermoen", description:"Se oss-aksjon med NMCU.", eventType:"stand", department:av, subgroup:null },
      { title:"Kjøretur med Tertitten MC", date:`${y}-05-17T08:45`, location:"Joker Blaker", description:"Kjøretur med Tertitten MC.", eventType:"tur", department:av, subgroup:null },
      { title:"Pinsetur", date:`${y}-05-22T00:00`, location:null, description:"Pinsetur 22.–25. mai.", eventType:"tur", department:av, subgroup:null },
      { title:"Trafikksikkerhetsdag", date:`${y}-05-30T00:00`, location:"Lillestrøm trafikkstasjon", description:"Trafikksikkerhetsdag.", eventType:"kurs", department:av, subgroup:null },
      { title:"Motordilla Årnes", date:`${y}-06-06T00:00`, location:"Årnes", description:"Motordilla-arrangement.", eventType:"stand", department:av, subgroup:null },
      { title:"Sikker på MC – Fetsund", date:`${y}-06-08T18:00`, location:"YX-stasjon Fetsund", description:"Sikker på MC-kurs.", eventType:"kurs", department:av, subgroup:null },
      { title:"Sikker på MC – Gardermoen", date:`${y}-06-09T00:00`, location:"GA-terminal Gardermoen", description:"Sikker på MC-kurs ved Gardermoen.", eventType:"kurs", department:av, subgroup:null },
      { title:"Senior trafikkurs", date:`${y}-06-15T00:00`, location:"Jessheim/NAF senter Rælingen", description:"Senior trafikkurs.", eventType:"kurs", department:av, subgroup:null },
      { title:"Sikker på MC – Bjørkelangen", date:`${y}-06-15T00:00`, location:"Gaustal landhandleri", description:"Sikker på MC-kurs Bjørkelangen.", eventType:"kurs", department:av, subgroup:null },
      { title:"Eidsvolldagene", date:`${y}-06-18T00:00`, location:"Eidsvoll", description:"Eidsvolldagene 18.–21. juni.", eventType:"stand", department:av, subgroup:null },
      { title:"MC Landstreff Røros", date:`${y}-07-03T00:00`, location:"Røros", description:"MC landstreff 3.–5. juli.", eventType:"tur", department:av, subgroup:null },
      { title:"Bike & Beach Horten", date:`${y}-07-24T00:00`, location:"Prestegårdsstranda, Horten", description:"Bike & Beach 24.–26. juli.", eventType:"stand", department:av, subgroup:null },
      { title:"Fellestreff Hamar", date:`${y}-08-05T00:00`, location:"Avreise Esso Jessheim", description:"Fellestreff til Hamar.", eventType:"tur", department:av, subgroup:null },
      { title:"Krødern Kro", date:`${y}-08-08T10:00`, location:"Avreise Gardermoen", description:"MC-tur til Krødern Kro.", eventType:"tur", department:av, subgroup:null },
      { title:"Trollrally Fyresdal", date:`${y}-08-28T00:00`, location:"Fyresdal", description:"Trollrally 28.–30. august.", eventType:"tur", department:av, subgroup:null },
      { title:"Høsttur Gålå", date:`${y}-09-04T00:00`, location:"Gålå", description:"Høsttur Gålå 4.–6. september.", eventType:"tur", department:av, subgroup:null },
      { title:"Oktobersamling", date:`${y}-10-10T00:00`, location:"NAF senter Rælingen", description:"Oktobersamling for MC.", eventType:"stand", department:av, subgroup:null },
      { title:"Refleksaksjonen Romerike", date:`${y}-10-15T00:00`, location:"Romerike", description:"Refleksaksjon for trafikksikkerhet.", eventType:"stand", department:av, subgroup:null },
      { title:"Oslo Motor Show", date:`${y}-10-23T00:00`, location:"NOVA spektrum", description:"Oslo Motor Show 23.–25. oktober.", eventType:"stand", department:av, subgroup:null },
      { title:"Julebord MC", date:`${y}-11-21T00:00`, location:null, description:"Julebord for MC-avdelingen.", eventType:"stand", department:av, subgroup:null },
    ], mock: true });
  }

  const useYear = Number(targetYear) || new Date().getFullYear();
  const nextYear = useYear + 1;
  // Build subgroup context for the prompt
  const subgroupList = Array.isArray(subgroupsFromBody) && subgroupsFromBody.length
    ? subgroupsFromBody
    : [];
  const subgroupPromptSection = subgroupList.length
    ? `\n\nAvdelingen har disse undergruppene – bruk id-en fra listen nedenfor:\n${
        subgroupList.map(function(u){ return '  id: "' + u.id + '" → navn: "' + u.name + '"'; }).join("\n")
      }\n\nPDF-en kan ha en Kategori-kolonne med verdier som "MC", "Lokalavdeling" eller "Lokalavdeling, MC".\nBruk denne til å sette subgroup: Kategori "MC" → bruk MC-undergruppen. "Lokalavdeling" → bruk lokalavdeling-undergruppen. Begge nevnt eller usikkert → null.\nLegg til \"subgroup\": \"<id>\" i JSON-objektet, eller null.`
    : '';

  const prompt = `You are an assistant that reads event schedules for motorcycle clubs and extracts event information.

Les denne terminlisten og returner KUN et JSON-array med events. Ingen annen tekst, ingen markdown, ingen forklaring.

Format per event:
{
  "title": "short, descriptive title",
  "date": "YYYY-MM-DDTHH:mm" eller null hvis ukjent,
  "location": "sted" eller null,
  "description": "beskrivelse av eventet, maks 2-3 setninger",
  "eventType": "mote", "stand", "kurs" eller "tur",
  "department": "${deptFromBody || "NAF MC Romerike"}",
  "subgroup": null
}${subgroupPromptSection}

Regler:
- VIKTIG: Bruk alltid år ${useYear} for alle datoer, uansett hva som står i filen – selv om filen sier ${useYear - 1} eller et annet år
- Unntak: Hvis terminlisten inneholder events tidlig neste år (f.eks. Årsmøte i januar/februar) bruk ${nextYear} for disse
- For datoperioder (f.eks. 22.-25.05) bruk startdatoen
- eventType = "kurs" for courses, safety days, workshops. eventType = "tur" for driving tours, trips. Otherwise "stand"
- Ignorer rene administrative linjer uten event-innhold
- Bevar norsk tekst som den er`;

  try {
    let messageContent;

    if (fileType === "excel") {
      // Excel er konvertert til CSV-tekst på klienten
      const csvText = decodeURIComponent(escape(atob(base64)));
      messageContent = [
        { type: "text", text: "Her er innholdet fra Excel-filen (konvertert til CSV):\n\n" + csvText + "\n\n" + prompt }
      ];
    } else {
      // PDF sendes som base64 dokument
      messageContent = [
        { type: "document", source: { type: "base64", media_type: "application/pdf", data: base64 } },
        { type: "text", text: prompt }
      ];
    }

    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "pdfs-2024-09-25",
        "x-api-key": process.env.ANTHROPIC_API_KEY
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 8000,
        system: "You are a data extraction assistant. You output ONLY valid JSON arrays, nothing else. No explanations, no markdown, no commentary. Just the raw JSON array starting with [ and ending with ].",
        messages: [{ role: "user", content: messageContent }]
      })
    });
    const rawResp = await r.text();
    let data;
    try { data = JSON.parse(rawResp); }
    catch(jsonErr) {
      console.error("[parse-pdf] Non-JSON from Anthropic:", r.status, rawResp.slice(0, 300));
      return res.status(500).json({ error: "Ugyldig svar fra AI (HTTP " + r.status + "): " + rawResp.slice(0, 120) });
    }
    if (!r.ok) {
      console.error("[parse-pdf] Anthropic error:", r.status, JSON.stringify(data));
      return res.status(500).json({ error: (data.error && data.error.message) || "AI-feil (HTTP " + r.status + ")" });
    }
    const raw = data.content.map(function(c){ return c.text || ""; }).join("").trim();
    console.log("[parse-pdf] AI response length:", raw.length, "| preview:", raw.slice(0, 100));

    // Extract JSON array robustly
    // 1. Try stripping code fences first
    let clean = raw.replace(/^```json\s*/i, "").replace(/```\s*$/i, "").trim();
    // 2. Find the outermost [ ... ]
    const arrStart = clean.indexOf("[");
    const arrEnd   = clean.lastIndexOf("]");
    if (arrStart === -1) {
      console.error("[parse-pdf] No JSON array found. Full response:", raw.slice(0, 500));
      return res.status(500).json({
        error: "AI returnerte ikke et JSON-array. Svar: " + raw.slice(0, 150)
      });
    }
    if (arrEnd === -1 || arrEnd <= arrStart) {
      console.error("[parse-pdf] JSON truncated (no closing bracket). Response length:", raw.length, "| max_tokens may be too low");
      return res.status(500).json({
        error: "AI-svaret ble avkortet – for mange events i PDF-en. Kontakt administrator."
      });
    }
    let events;
    try {
      events = JSON.parse(clean.slice(arrStart, arrEnd + 1));
    } catch(pe) {
      console.error("[parse-pdf] JSON parse error:", pe.message, "| slice:", clean.slice(arrStart, arrStart + 200));
      return res.status(500).json({ error: "Kunne ikke tolke AI-responsen: " + pe.message });
    }
    if (!Array.isArray(events)) {
      return res.status(500).json({ error: "AI returnerte ikke et array" });
    }
    console.log("[parse-pdf] Extracted", events.length, "events");
    res.json({ events });
  } catch(e) {
    console.error("[parse-pdf] Exception:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Members API ─────────────────────────────────────────────────
app.get("/api/members", auth, function(req, res) {
  const me = req.session.user;
  const members = readJSON(MEMBERS_FILE);
  if (me.role === "admin") return res.json(members);
  var myDeptIds = getAccessList(me).map(function(t){ return t.department; });
  if (!myDeptIds.length) return res.json([]);
  res.json(members.filter(function(m){ return myDeptIds.indexOf(m.department) !== -1; }));
});

app.post("/api/members/import", auth, function(req, res) {
  const me = req.session.user;
  var myAccessImport = getAccessList(me);
  var isManagerImport = me.role === "admin" || myAccessImport.some(function(t){
    return (t.role === "department_manager" || t.role === "avdelingsleder") || (t.role === "subgroup_manager" || t.role === "undergruppeansvarlig");
  });
  if (!isManagerImport) return res.status(403).json({ error: "Ingen tilgang" });

  var departmentId = me.role === "admin" ? null : (myAccessImport.length ? myAccessImport[0].department : null);
  if (me.role !== "admin" && !departmentId)
    return res.status(400).json({ error: "Ingen avdeling knyttet til din konto" });

  const incoming = req.body.members;
  if (!Array.isArray(incoming)) return res.status(400).json({ error: "Ugyldig format" });
  const existing = readJSON(MEMBERS_FILE);
  const emails   = new Set(existing.map(function(m) { return m.email.toLowerCase(); }));
  var added = 0;
  incoming.forEach(function(m) {
    const email = (m.email || "").trim().toLowerCase().slice(0, 200);
    if (!email || emails.has(email)) return;
    emails.add(email);
    existing.push({
      id: uuid(),
      name: (m.name || "").trim().slice(0, 100),
      email: email,
      phone: (m.phone || "").trim().slice(0, 30),
      department: departmentId,   // null for admin-import
      addedAt: new Date().toISOString()
    });
    added++;
  });
  writeJSON(MEMBERS_FILE, existing);
  res.json({ ok: true, added: added, total: existing.length });
});

app.delete("/api/members/:id", auth, function(req, res) {
  const me = req.session.user;
  if (me.role !== "admin" && me.role !== "avdelingsleder")
    return res.status(403).json({ error: "Ingen tilgang" });
  const members = readJSON(MEMBERS_FILE);
  const target = members.find(function(m){ return m.id === req.params.id; });
  if (!target) return res.status(404).json({ error: "Ikke funnet" });
  if (me.role === "department_manager" || me.role === "avdelingsleder") {
    var myDeptIds = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
    if (myDeptIds.indexOf(target.department) === -1)
      return res.status(403).json({ error: "Ingen tilgang til dette medlemmet" });
  }
  writeJSON(MEMBERS_FILE, members.filter(function(m){ return m.id !== req.params.id; }));
  res.json({ ok: true });
});

// ── Wishes API ───────────────────────────────────────────────────
app.get("/api/wishes", auth, function(req, res) {
  const wishes = readJSON(WISHES_F);
  // Avdelingsleder ser kun sine egne, admin ser alle
  if (req.session.user.role === "admin") return res.json(wishes);
  res.json(wishes.filter(function(w) { return w.userId === req.session.user.id; }));
});

app.post("/api/wishes", auth, function(req, res) {
  const text = (req.body.text || "").trim();
  if (!text) return res.status(400).json({ error: "Tekst er påkrevd" });
  const wishes = readJSON(WISHES_F);
  wishes.unshift({
    id: uuid(),
    text: text,
    userId:   req.session.user.id,
    userName: req.session.user.name || req.session.user.email,
    userEmail: req.session.user.email,
    createdAt: new Date().toISOString(),
    status: "open",   // open | done | wontfix
    adminNote: "",
  });
  writeJSON(WISHES_F, wishes);
  res.json({ ok: true });
});

app.put("/api/wishes/:id", auth, adminOnly, function(req, res) {
  const wishes = readJSON(WISHES_F);
  const i = wishes.findIndex(function(w) { return w.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  if (req.body.status    !== undefined) wishes[i].status    = req.body.status;
  if (req.body.adminNote !== undefined) wishes[i].adminNote = req.body.adminNote;
  writeJSON(WISHES_F, wishes);
  res.json({ ok: true });
});

app.delete("/api/wishes/:id", auth, adminOnly, function(req, res) {
  writeJSON(WISHES_F, readJSON(WISHES_F).filter(function(w) { return w.id !== req.params.id; }));
  res.json({ ok: true });
});

// ── Frivillige ───────────────────────────────────────────────────
app.get("/api/volunteers", auth, managerOrAdmin, function(req, res) {
  var all = readJSON(VOLUNTEERS_FILE) || [];
  var me = req.session.user;
  if (me.role === "admin") return res.json(all);
  // Avdelingsleder ser kun egne frivillige
  var myDeptIds = getAccessList(me).map(function(t){ return t.department; });
  var myVols = all.filter(function(v) {
    var volDepts = Array.isArray(v.departments) && v.departments.length
      ? v.departments : (v.department ? [v.department] : []);
    if (!volDepts.length) return true;
    return volDepts.some(function(did) { return myDeptIds.indexOf(did) !== -1; });
  });
  res.json(myVols);
});

app.post("/api/volunteers", auth, managerOrAdmin, function(req, res) {
  var volName       = (req.body.name || "").trim();
  var email         = (req.body.email || "").toLowerCase().trim();
  var phone         = (req.body.phone || "").trim();
  var volunteerDept = req.body.department || null;
  if (!volName) return res.status(400).json({ error: "Navn er påkrevd" });
  var me = req.session.user;
  if (me.role !== "admin") {
    var myDeptIds = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
    // Bruk egen avdeling hvis ingen er spesifisert
    if (!volunteerDept) volunteerDept = myDeptIds[0] || null;
    if (!volunteerDept || myDeptIds.indexOf(volunteerDept) === -1)
      return res.status(403).json({ error: "Ingen tilgang til denne avdelingen" });
  }
  var all = readJSON(VOLUNTEERS_FILE) || [];
  // Ny modell: departments[] + activeDepartment
  var departments_in = Array.isArray(req.body.departments) ? req.body.departments : [];
  if (!departments_in.length && volunteerDept) departments_in = [volunteerDept];
  var activeDept = req.body.activeDepartment || departments_in[0] || volunteerDept || null;
  // Sjekk at alle avdelinger er tillatt for ikke-admin
  if (me.role !== "admin") {
    var myDeptIds2 = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
    if (departments_in.some(function(did) { return myDeptIds2.indexOf(did) === -1; }))
      return res.status(403).json({ error: "Ingen tilgang til én eller flere avdelinger" });
    if (!departments_in.length) departments_in = [myDeptIds2[0] || null].filter(Boolean);
    activeDept = myDeptIds2.includes(activeDept) ? activeDept : (departments_in[0] || null);
  }
  var v = {
    id: uuid(), name: volName, email: email, phone: phone,
    departments: departments_in,
    activeDepartment: activeDept,
    department: activeDept, // bakoverkompatibilitet
    events: [], createdAt: new Date().toISOString()
  };
  all.push(v);
  writeJSON(VOLUNTEERS_FILE, all);
  res.json(v);
});

app.put("/api/volunteers/:id", auth, managerOrAdmin, function(req, res) {
  var all = readJSON(VOLUNTEERS_FILE) || [];
  var i = all.findIndex(function(v){ return v.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  var me = req.session.user;
  if (me.role !== "admin") {
    var myDeptIds = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
    if (myDeptIds.indexOf(all[i].department) === -1) return res.status(403).json({ error: "Ingen tilgang" });
  }
  if (req.body.name    !== undefined) all[i].name    = req.body.name.trim();
  if (req.body.email   !== undefined) all[i].email   = (req.body.email || "").toLowerCase().trim();
  if (req.body.phone   !== undefined) all[i].phone   = (req.body.phone || "").trim();
  // Ny modell: departments[] + activeDepartment
  if (Array.isArray(req.body.departments)) {
    var depts_upd = req.body.departments;
    if (me.role !== "admin") {
      var myDeptIds3 = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
      depts_upd = depts_upd.filter(function(did) { return myDeptIds3.indexOf(did) !== -1; });
    }
    all[i].departments = depts_upd;
    var newActive = req.body.activeDepartment || null;
    if (!newActive || depts_upd.indexOf(newActive) === -1) newActive = depts_upd[0] || null;
    all[i].activeDepartment = newActive;
    all[i].department = newActive; // bakoverkompatibilitet
  }
  writeJSON(VOLUNTEERS_FILE, all);
  res.json(all[i]);
});

app.delete("/api/volunteers/:id", auth, managerOrAdmin, function(req, res) {
  var all = readJSON(VOLUNTEERS_FILE) || [];
  var v = all.find(function(x){ return x.id === req.params.id; });
  if (!v) return res.status(404).json({ error: "Ikke funnet" });
  var me = req.session.user;
  if (me.role !== "admin") {
    var myDeptIds = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === me.id; }) || {}).map(function(t){ return t.department; });
    if (myDeptIds.indexOf(v.department) === -1) return res.status(403).json({ error: "Ingen tilgang" });
  }
  writeJSON(VOLUNTEERS_FILE, all.filter(function(x){ return x.id !== req.params.id; }));
  res.json({ ok: true });
});

app.post("/api/volunteers/:id/events/:evId", auth, managerOrAdmin, function(req, res) {
  var all = readJSON(VOLUNTEERS_FILE) || [];
  var i = all.findIndex(function(v){ return v.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  if (!all[i].events) all[i].events = [];
  if (all[i].events.indexOf(req.params.evId) === -1) all[i].events.push(req.params.evId);
  writeJSON(VOLUNTEERS_FILE, all);
  res.json(all[i]);
});

app.delete("/api/volunteers/:id/events/:evId", auth, managerOrAdmin, function(req, res) {
  var all = readJSON(VOLUNTEERS_FILE) || [];
  var i = all.findIndex(function(v){ return v.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  all[i].events = (all[i].events || []).filter(function(e){ return e !== req.params.evId; });
  writeJSON(VOLUNTEERS_FILE, all);
  res.json(all[i]);
});

// ── Dev-logg API (kun DEVLOG_OWNER) ─────────────────────────────
function devlogAuth(req, res, next) {
  if (!req.session.user || req.session.user.email !== DEVLOG_OWNER)
    return res.status(403).json({ error: "Ingen tilgang" });
  next();
}
function readDevlog() {
  try { return JSON.parse(fs.readFileSync(DEVLOG_F)); }
  catch(e) { return { entries: [] }; }
}

app.get("/api/devlog", auth, devlogAuth, function(req, res) {
  res.json(readDevlog());
});

app.post("/api/devlog/entries", auth, devlogAuth, function(req, res) {
  const log = readDevlog();
  log.entries.unshift({ id: uuid(), createdAt: new Date().toISOString(), title: req.body.title || "", content: req.body.content || "", tags: Array.isArray(req.body.tags) ? req.body.tags : [] });
  fs.writeFileSync(DEVLOG_F, JSON.stringify(log, null, 2));
  res.json({ ok: true });
});

app.put("/api/devlog/entries/:id", auth, devlogAuth, function(req, res) {
  const log = readDevlog();
  const i = log.entries.findIndex(function(e) { return e.id === req.params.id; });
  if (i < 0) return res.status(404).json({ error: "Ikke funnet" });
  if (req.body.title   !== undefined) log.entries[i].title   = req.body.title;
  if (req.body.content !== undefined) log.entries[i].content = req.body.content;
  if (req.body.tags    !== undefined) log.entries[i].tags    = Array.isArray(req.body.tags) ? req.body.tags : [];
  log.entries[i].updatedAt = new Date().toISOString();
  fs.writeFileSync(DEVLOG_F, JSON.stringify(log, null, 2));
  res.json({ ok: true });
});

app.delete("/api/devlog/entries/:id", auth, devlogAuth, function(req, res) {
  const log = readDevlog();
  log.entries = log.entries.filter(function(e) { return e.id !== req.params.id; });
  fs.writeFileSync(DEVLOG_F, JSON.stringify(log, null, 2));
  res.json({ ok: true });
});
function serveDepartmentPage(dept, req, res) {
  var events   = readJSON(EVENTS_FILE);
  var settings = getSettings();
  var siteName = settings.siteName || "Events Admin";
  var domain   = DOMAIN;
  var now      = Date.now();
  var ago30    = now - 7 * 24 * 60 * 60 * 1000;

  // Filter by department + show 30 days back
  var filtered = events.filter(function(ev) {
    if (ev.department !== dept.id) return false;
    if (!ev.date) return true;
    return new Date(ev.date).getTime() >= ago30;
  });

  filtered.sort(function(a, b) {
    if (!a.date && !b.date) return 0;
    if (!a.date) return -1; // uten dato øverst
    if (!b.date) return 1;
    return new Date(a.date) - new Date(b.date);
  });

  var subgroups = dept.subgroups || [];

  // Bygg kolonne-data: én per subgroup + én for events uten subgroup
  var columns = [];

  var utenUg = filtered.filter(function(ev) { return !ev.subgroup; });
  if (utenUg.length > 0) {
    columns.push({ id: null, label: subgroups.length > 0 ? "Generelt" : "Arrangementer", events: utenUg });
  }

  subgroups.forEach(function(ug) {
    var ugEvents = filtered.filter(function(ev) { return ev.subgroup === ug.id; });
    if (ugEvents.length > 0) {
      columns.push({ id: ug.id, label: ug.name, events: ugEvents });
    }
  });

  // ── Kort-generator ───────────────────────────────────────────────
  function evCard(ev) {
    var hasDate = !!ev.date;
    var evDate  = hasDate ? new Date(ev.date) : null;
    var today   = new Date();
    var todayDate = today.toISOString().slice(0,10);

    // Beregn slutt-tidspunkt
    // Prioritet: endDate+endTime > endDate > endTime > startdato 23:59
    var endMs;
    if (ev.endDate) {
      var endD = new Date(ev.endDate);
      if (ev.endTime) {
        var ep = ev.endTime.split(":");
        endD.setHours(parseInt(ep[0],10), parseInt(ep[1],10), 0, 0);
      } else {
        endD.setHours(23, 59, 59, 999);
      }
      endMs = endD.getTime();
    } else if (evDate) {
      var endSameDay = new Date(evDate);
      if (ev.endTime) {
        var ep2 = ev.endTime.split(":");
        endSameDay.setHours(parseInt(ep2[0],10), parseInt(ep2[1],10), 0, 0);
        // Slutter etter midnatt?
        if (endSameDay <= evDate) endSameDay.setDate(endSameDay.getDate() + 1);
      } else {
        endSameDay.setHours(23, 59, 59, 999);
      }
      endMs = endSameDay.getTime();
    }

    var startMs = evDate ? evDate.getTime() : null;
    var isPast   = startMs ? endMs < now : false;
    var isActive = startMs && startMs <= now && endMs > now;

    // Dato-kolumnen lyser på alle dager eventet strekker seg over
    var eventStartDate = hasDate ? ev.date.slice(0,10) : null;
    var eventEndDate   = ev.endDate || eventStartDate;
    var dateColLit     = eventStartDate && todayDate >= eventStartDate && todayDate <= eventEndDate;

    var timeStr = (hasDate && ev.date.length > 10) ? evDate.toLocaleTimeString("en-GB", {hour:"2-digit",minute:"2-digit"}) : null;
    var endStr  = ev.endTime ? ev.endTime.slice(0,5) : null;
    var yearStr = evDate ? evDate.getFullYear() : null;
    var typeLabel = getTypeLabel(ev.eventType, getSettings());
    var typeCls   = ev.eventType === "kurs" ? "type-kurs" : ev.eventType === "tur" ? "type-tur" : "type-stand";
    var url       = "https://" + ev.slug + "." + domain;
    var regs      = (ev.registrations || []).length;

    var cls = "ev-card";
    if (isPast)    cls += " past";
    if (isActive)  cls += " active";

    // Minimap og stopp-info for tur-events med rute
    var minimap = "";
    if (ev.eventType === "tur" && ev.route && ev.route.days && ev.route.days.length) {
      var days = ev.route.days;

      // Samle alle steder med koordinater
      var places = [];
      days.forEach(function(d) {
        (d.etapper || []).forEach(function(e) {
          if (e._lat && e._lon)       places.push({ lat: e._lat,     lon: e._lon,     type: e.type });
          if (e._fra_lat && e._fra_lon) places.push({ lat: e._fra_lat, lon: e._fra_lon, type: "start" });
        });
      });
      // Deduplicate
      var seen = new Set();
      places = places.filter(function(p) {
        var k = p.lat.toFixed(4) + "," + p.lon.toFixed(4);
        if (seen.has(k)) return false; seen.add(k); return true;
      });

      // Stopp-oppsummering per dag
      var STOP_ICONS = { start:"🚀", stopp:"🅿️", lunsj:"🍽️", middag:"🍷", hotell:"🏨", bensin:"⛽", opplevelse:"🎯", slutt:"🏁" };
      var OPPL_ICONS = { museum:"🏛️", natur:"🌿", utsikt:"🏔️", historisk:"🏰", aktivitet:"🎭", kultur:"🎨", mat:"🍴", annet:"⭐" };
      var getStopIcon = function(s) { return s.type === "opplevelse" ? (OPPL_ICONS[s.opplevelseSubtype] || "🎯") : (STOP_ICONS[s.type] || "📍"); };
      var dayRows = days.map(function(d, di) {
        var totalKm = (d.etapper||[]).reduce(function(s,e){ return s+(parseFloat(e.km)||0); }, 0);
        var stops = (d.etapper||[]).filter(function(e){ return ["lunsj","middag","hotell","opplevelse","stopp","bensin"].includes(e.type); });
        var stopIcons = stops.map(getStopIcon).join("");
        var opplevelser = stops.filter(function(s){ return s.type === "opplevelse"; }).map(function(s){ return (OPPL_ICONS[s.opplevelseSubtype] || "🎯") + " " + (s.notat || s.til || ""); }).filter(Boolean);
        return '<div style="background:#1a1a1a;border-radius:3px;padding:2px 4px">'
          + '<div style="color:#d8b4fe;font-weight:700;font-size:.65rem">Dag '+(di+1)+'</div>'
          + '<div style="color:#666;font-size:.65rem">' + (totalKm > 0 ? Math.round(totalKm)+' km' : '–') + (stopIcons ? ' '+stopIcons : '') + '</div>'
          + (opplevelser.length ? '<div style="color:#f5c500;font-size:.6rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+escHtml(opplevelser[0])+'</div>' : '')
          + '</div>';
      }).join("");

      var cols = days.length <= 3 ? days.length : 3;

      // Kart-seksjon: Leaflet minimap hvis koordinater finnes, ellers bilde eller placeholder
      var mapSection = "";
      var hasCoords = places.length >= 2;
      var mapId = "mm-" + ev.id;

      // Fallback: hent koordinater fra stedsnavn hvis de mangler
      if (!hasCoords && days.length) {
        var allNames = [];
        days.forEach(function(d) {
          (d.etapper||[]).forEach(function(e) {
            if (e.fra && !allNames.includes(e.fra)) allNames.push(e.fra);
            if (e.til && !allNames.includes(e.til)) allNames.push(e.til);
          });
        });
        // Bruk cached koordinater fra _geocodeCache på serveren
        if (!global._geocodeCache) global._geocodeCache = {};
        allNames.forEach(function(name) {
          var cached = global._geocodeCache[name];
          if (cached) places.push({ lat: cached.lat, lon: cached.lon, type: "wpt" });
        });
        hasCoords = places.length >= 2;
        // Trigger async bakgrunns-geocoding uten å blokkere side-rendering
        if (!hasCoords && allNames.length >= 2) {
          (async function() {
            var sleep = function(ms) { return new Promise(function(r){ setTimeout(r,ms); }); };
            for (var ni = 0; ni < Math.min(allNames.length, 5); ni++) {
              var nm = allNames[ni];
              if (global._geocodeCache[nm]) continue;
              try {
                var gr = await fetch("https://nominatim.openstreetmap.org/search?format=json&limit=1&q="+encodeURIComponent(nm), { headers:{ "User-Agent":"EventsAdmin/1.0" } });
                var gd = await gr.json();
                if (gd && gd[0]) global._geocodeCache[nm] = { lat: parseFloat(gd[0].lat), lon: parseFloat(gd[0].lon) };
              } catch(ge) {}
              await sleep(400);
            }
          })();
        }
      }

      if (hasCoords) {
        // Beregn bbox for kartet
        var lats = places.map(function(p){ return p.lat; });
        var lons = places.map(function(p){ return p.lon; });
        var minLat = Math.min.apply(null, lats), maxLat = Math.max.apply(null, lats);
        var minLon = Math.min.apply(null, lons), maxLon = Math.max.apply(null, lons);
        var pad = 0.15;
        var b = [minLon-pad, minLat-pad, maxLon+pad, maxLat+pad];
        // Bruk OpenStreetMap static tiles via bbox
        var staticUrl = "https://www.openstreetmap.org/export/embed.html?bbox="
          + b[0]+"%2C"+b[1]+"%2C"+b[2]+"%2C"+b[3]
          + "&layer=mapnik";
        // Marker-overlay som SVG
        var viewW = 140, viewH = 90;
        function toSvg(lat, lon) {
          var x = (lon - b[0]) / (b[2] - b[0]) * viewW;
          var y = (1 - (lat - b[1]) / (b[3] - b[1])) * viewH;
          return { x: Math.round(x), y: Math.round(y) };
        }
        var svgDots = places.map(function(p, i) {
          var pt = toSvg(p.lat, p.lon);
          var isFirst = i === 0, isLast = i === places.length - 1;
          var col = isFirst ? "#4ade80" : isLast ? "#f87171" : "#d8b4fe";
          var r = isFirst || isLast ? 5 : 3;
          return '<circle cx="'+pt.x+'" cy="'+pt.y+'" r="'+r+'" fill="'+col+'" stroke="#000" stroke-width="1"/>';
        }).join("");
        // Draw rough route line
        var svgLine = '<polyline points="' + places.map(function(p){
          var pt = toSvg(p.lat, p.lon);
          return pt.x+","+pt.y;
        }).join(" ") + '" fill="none" stroke="#d8b4fe" stroke-width="1.5" stroke-opacity="0.7"/>';

        mapSection = '<div style="height:90px;background:#0a0a1a;position:relative;overflow:hidden">'
          + '<iframe src="' + staticUrl + '" style="width:250%;height:250%;transform:scale(0.4);transform-origin:0 0;border:0;pointer-events:none;filter:brightness(0.7) saturate(0.6)" scrolling="no"></iframe>'
          + '<svg style="position:absolute;inset:0;width:100%;height:100%;pointer-events:none" viewBox="0 0 '+viewW+' '+viewH+'" xmlns="http://www.w3.org/2000/svg">'
          + svgLine + svgDots
          + '</svg>'
          + '</div>';
      } else if (ev.image) {
        mapSection = '<div style="height:90px;overflow:hidden">'
          + '<img src="' + escHtml(ev.image) + '" style="width:100%;height:100%;object-fit:cover"/>'
          + '</div>';
      } else {
        mapSection = '<div style="height:90px;background:linear-gradient(135deg,#2d1a3a,#1a1200);display:flex;align-items:center;justify-content:center;font-size:2rem">🏍️</div>';
      }

      minimap = '<div style="display:flex;flex-direction:column;width:150px;min-width:150px;flex-shrink:0;overflow:hidden;border-left:1px solid #2a2a2a">'
        + mapSection
        + '<div style="padding:3px 5px;background:#161616;border-top:1px solid #2a2a2a;display:grid;grid-template-columns:repeat('+cols+',1fr);gap:2px">'
        + dayRows
        + '</div>'
        + '</div>';

    } else if (ev.image) {
      minimap = '<div style="width:140px;min-width:140px;height:90px;flex-shrink:0;overflow:hidden">'
        + '<img src="' + escHtml(ev.image) + '" style="width:100%;height:100%;object-fit:cover"/>'
        + '</div>';
    }

    return '<a class="' + cls + '" href="' + escHtml(url) + '" style="display:flex;align-items:stretch">'
      + '<div class="ev-date-col"' + (dateColLit ? ' style="background:var(--y)"' : '') + '>'
      + (evDate
        ? '<div class="ev-day"' + (dateColLit ? ' style="color:#111"' : '') + '>' + evDate.getDate() + '</div>'
        + '<div class="ev-month"' + (dateColLit ? ' style="color:#333"' : '') + '>' + evDate.toLocaleDateString("en-GB",{month:"short"}) + '</div>'
        + '<div class="ev-year"' + (dateColLit ? ' style="color:#555"' : '') + '>' + yearStr + '</div>'
        : '<div class="ev-day" style="font-size:.7rem;color:#888">Dato</div><div class="ev-month" style="color:#666">kommer</div>')
      + '</div>'
      + '<div class="ev-body" style="flex:1;min-width:0">'
      + '<div class="ev-top"><span class="type-badge ' + typeCls + '">' + typeLabel + '</span>'
      + (isActive ? '<span class="active-badge">Pågående nå</span>' : '')
      + (dateColLit && !isActive ? '<span class="today-badge">I dag</span>' : '')
      + (isPast ? '<span class="past-badge">Avholdt</span>' : '') + '</div>'
      + '<div class="ev-title">' + escHtml(ev.title) + '</div>'
      + (timeStr ? '<div class="ev-meta">🕐 ' + timeStr + (endStr ? '–' + endStr : '') + (ev.endDate && ev.endDate !== ev.date.slice(0,10) ? ' (' + new Date(ev.endDate).toLocaleDateString("en-GB",{day:"numeric",month:"short"}) + ')' : '') + '</div>' : '')
      + (ev.location ? '<div class="ev-meta">📍 ' + escHtml(ev.location) + '</div>' : '')
      + (regs > 0 && ev.showParticipants ? '<div class="ev-meta">👥 ' + regs + ' registered</div>' : '')
      + '</div>'
      + minimap
      + '<div class="ev-arrow"' + (dateColLit ? ' style="color:var(--y)"' : '') + '>→</div>'
      + '</a>';
  }

  // ── Finn pågående og neste aktivitet (header-spotlight) ──────────
  function getEndMs(ev) {
    if (!ev.date) return null;
    if (ev.endDate) {
      var ed = new Date(ev.endDate);
      if (ev.endTime) { var p=ev.endTime.split(":"); ed.setHours(+p[0],+p[1],0,0); }
      else ed.setHours(23,59,59,999);
      return ed.getTime();
    }
    var ed2 = new Date(ev.date);
    if (ev.endTime) { var p2=ev.endTime.split(":"); ed2.setHours(+p2[0],+p2[1],0,0); if(ed2<=new Date(ev.date)) ed2.setDate(ed2.getDate()+1); }
    else ed2.setHours(23,59,59,999);
    return ed2.getTime();
  }

  // All events for the department (incl. older than 7d for active)
  var allAvdEvents = events.filter(function(ev) { return ev.department === dept.id && ev.date; });
  var spotPagaende = allAvdEvents.filter(function(ev) {
    var sm = new Date(ev.date).getTime();
    var em = getEndMs(ev);
    return sm <= now && em && em >= now;
  });
  spotPagaende.sort(function(a,b) { return new Date(a.date)-new Date(b.date); });

  var spotKommende = allAvdEvents.filter(function(ev) {
    return new Date(ev.date).getTime() > now;
  });
  spotKommende.sort(function(a,b) { return new Date(a.date)-new Date(b.date); });
  var spotNeste = spotKommende.length > 0 ? spotKommende[0] : null;

  // ── Spotlight-kort (stor versjon for header) ──────────────────────
  function spotCard(ev, mode) {
    // mode: "active" | "next" | "empty-active" | "empty-next"
    var isEmpty = mode.indexOf("empty") === 0;
    var isActive = mode === "active";
    var url = isEmpty ? "#" : "https://" + ev.slug + "." + domain;

    var label = isActive ? "Pågående nå" : "Neste aktivitet";
    var labelColor = isActive ? "var(--y)" : "#888";
    var borderColor = isActive ? "var(--y)" : "#2a2a2a";
    var bgColor = isActive ? "rgba(245,197,0,.06)" : "rgba(255,255,255,.02)";
    var animCls = isActive ? " spot-pulse" : "";

    if (isEmpty) {
      var emptyText = isActive ? "Ingen pågående aktivitet" : "Ingen kommende aktiviteter";
      return '<a href="#" style="display:flex;align-items:stretch;background:' + bgColor + ';border:1px solid #222;border-radius:var(--r);text-decoration:none;color:#fff;overflow:hidden;opacity:.45;cursor:default;flex:1;min-width:0">'
        + '<div style="width:4px;background:#333;flex-shrink:0"></div>'
        + '<div style="padding:.85rem 1rem;flex:1;min-width:0">'
        + '<div style="font-size:.6rem;text-transform:uppercase;letter-spacing:.8px;color:#555;margin-bottom:.35rem">' + label + '</div>'
        + '<div style="font-size:.85rem;color:#555;font-style:italic">' + emptyText + '</div>'
        + '</div></a>';
    }

    var evDate = new Date(ev.date);
    var dayStr = evDate.getDate();
    var monStr = evDate.toLocaleDateString("en-GB",{month:"short"});
    var timeStr = ev.date.length > 10 ? evDate.toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"}) : null;
    var endStr  = ev.endTime ? ev.endTime.slice(0,5) : null;
    var typeLabel = getTypeLabel(ev.eventType, getSettings());
    var typeCls   = ev.eventType === "kurs" ? "type-kurs" : ev.eventType === "tur" ? "type-tur" : "type-stand";

    return '<a href="' + escHtml(url) + '" class="spot-card' + animCls + '" style="display:flex;align-items:stretch;background:' + bgColor + ';border:1px solid ' + borderColor + ';border-radius:var(--r);text-decoration:none;color:#fff;overflow:hidden;flex:1;min-width:0;transition:border-color .15s,transform .1s">'
      + '<div style="width:4px;background:' + labelColor + ';flex-shrink:0' + (isActive ? ';animation:spotbar 2s ease-in-out infinite' : '') + '"></div>'
      + '<div style="width:52px;background:#1e1e1e;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0;padding:.5rem 0;border-right:1px solid #2a2a2a">'
      + '<div style="font-size:1.5rem;font-weight:900;line-height:1;color:' + labelColor + '">' + dayStr + '</div>'
      + '<div style="font-size:.6rem;text-transform:uppercase;color:#888;letter-spacing:.4px">' + monStr + '</div>'
      + '</div>'
      + '<div style="padding:.7rem .9rem;flex:1;min-width:0">'
      + '<div style="font-size:.6rem;text-transform:uppercase;letter-spacing:.8px;color:' + labelColor + ';margin-bottom:.2rem;font-weight:700">' + label + '</div>'
      + '<div style="font-size:.95rem;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:.25rem">' + escHtml(ev.title) + '</div>'
      + '<div style="display:flex;gap:.3rem;flex-wrap:wrap;align-items:center">'
      + '<span class="type-badge ' + typeCls + '">' + typeLabel + '</span>'
      + (timeStr ? '<span style="font-size:.7rem;color:#888">🕐 ' + timeStr + (endStr ? '–'+endStr : '') + '</span>' : '')
      + (ev.location ? '<span style="font-size:.7rem;color:#888">📍 ' + escHtml(ev.location) + '</span>' : '')
      + '</div>'
      + '</div>'
      + '<div style="display:flex;align-items:center;padding:0 .75rem;color:' + labelColor + ';font-size:.9rem;flex-shrink:0">→</div>'
      + '</a>';
  }

  // ── CSS ──────────────────────────────────────────────────────────
  var colCount = Math.max(1, columns.length);
  var css = '*{box-sizing:border-box;margin:0;padding:0}'
    + 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#111;color:#fff;min-height:100vh}'
    + ':root{--y:#f5c500;--g:#1e1e1e;--g2:#2a2a2a;--r:8px}'
    + '.header{background:#1a1a1a;border-bottom:3px solid var(--y);display:flex;align-items:stretch;gap:0;min-height:90px}'
    + '.header-brand{display:flex;align-items:center;gap:.75rem;flex-shrink:0;padding:.85rem 1.5rem;border-right:1px solid #2a2a2a}'
    + '.header-logo{font-size:1.5rem;font-weight:900;color:var(--y);letter-spacing:-1px}'
    + '.header-title{font-size:1rem;font-weight:700;white-space:nowrap;line-height:1.2}'
    + '.header-sub{font-size:.75rem;color:#888;white-space:nowrap}'
    + '.header-spotlight{display:flex;gap:5rem;align-items:center;flex:1;justify-content:center}'
    + '@media(max-width:700px){.header{flex-wrap:wrap}.header-brand{border-right:none;padding-right:0}.header-spotlight{width:100%;flex-direction:column}}'
    + '.spot-card:hover{border-color:var(--y)!important;transform:translateY(-1px)}'
    + '@keyframes spotbar{0%,100%{opacity:1}50%{opacity:.4}}'
    + '@keyframes spotpulse{0%,100%{box-shadow:0 0 0 1px var(--y),0 0 8px 2px rgba(245,197,0,.2)}50%{box-shadow:0 0 0 2px var(--y),0 0 20px 6px rgba(245,197,0,.4)}}'
    + '.spot-pulse{animation:spotpulse 2s ease-in-out infinite}'
    + '.container{max-width:1200px;margin:0 auto;padding:1.5rem 1rem}'
    + '.cols{display:grid;grid-template-columns:repeat(' + colCount + ',1fr);gap:1rem;align-items:start}'
    + '@media(max-width:640px){.cols{grid-template-columns:1fr}}'
    + '.col-head{background:var(--g2);border-radius:var(--r) var(--r) 0 0;padding:.6rem 1rem;border-bottom:2px solid var(--y);display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem}'
    + '.col-head h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.8px;color:var(--y);font-weight:800}'
    + '.col-count{font-size:.72rem;background:#333;color:#888;padding:1px 7px;border-radius:20px;margin-left:auto}'
    + '.ev-card{display:flex;align-items:stretch;background:var(--g);border-radius:var(--r);margin-bottom:.6rem;text-decoration:none;color:#fff;overflow:hidden;border:1px solid #2a2a2a;transition:border-color .15s,transform .1s}'
    + '.ev-card:hover{border-color:var(--y);transform:translateY(-1px)}'
    + '.ev-card.past{opacity:.55}'
    + '.ev-card.active{border-color:var(--y);animation:pulse 2s ease-in-out infinite}'
    + '@keyframes pulse{0%,100%{box-shadow:0 0 0 1px var(--y),0 0 8px 2px rgba(245,197,0,.25)}50%{box-shadow:0 0 0 2px var(--y),0 0 18px 6px rgba(245,197,0,.45)}}'
    + '.today-badge{font-size:.6rem;font-weight:800;padding:2px 7px;border-radius:20px;background:#333;color:var(--y);text-transform:uppercase;letter-spacing:.5px}'
    + '.active-badge{font-size:.6rem;font-weight:800;padding:2px 7px;border-radius:20px;background:var(--y);color:#111;text-transform:uppercase;letter-spacing:.5px;animation:pulse 2s ease-in-out infinite}'
    + '.ev-date-col{width:52px;min-height:70px;background:#2a2a2a;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0;padding:.4rem 0}'
    + '.ev-day{font-size:1.4rem;font-weight:900;line-height:1;color:var(--y)}'
    + '.ev-month{font-size:.65rem;text-transform:uppercase;color:#888;letter-spacing:.5px}'
    + '.ev-year{font-size:.6rem;color:#555}'
    + '.ev-body{padding:.6rem .75rem;flex:1;min-width:0}'
    + '.ev-top{display:flex;gap:.3rem;margin-bottom:.3rem;align-items:center;flex-wrap:wrap}'
    + '.type-badge{font-size:.6rem;font-weight:700;padding:2px 6px;border-radius:20px;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}'
    + '.type-stand{background:#1a4a1a;color:#4caf50}'
    + '.type-kurs{background:#1a2a4a;color:#64b5f6}'
    + '.type-tur{background:#3a1a4a;color:#c084fc}'
    + '.past-badge{font-size:.6rem;color:#666;background:#222;padding:2px 6px;border-radius:20px}'
    + '.ug-badge{font-size:.6rem;color:#aaa;background:#2a2a2a;border:1px solid #3a3a3a;padding:2px 6px;border-radius:20px}'
    + '.ev-title{font-size:.88rem;font-weight:700;margin-bottom:.2rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'
    + '.ev-meta{font-size:.72rem;color:#777;margin-top:.1rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'
    + '.ev-arrow{display:flex;align-items:center;padding:0 .6rem;color:#333;font-size:1rem;flex-shrink:0}'
    + '.ev-card:hover .ev-arrow{color:var(--y)}'
    + '.empty-col{text-align:center;padding:2rem .5rem;color:#444;font-size:.82rem}'
    + 'footer{text-align:center;padding:2rem 1rem;font-size:.75rem;color:#333}'  + '.banner-wrap{background:transparent;position:relative;height:100%;display:flex;align-items:stretch;width:100%}'  + '.banner-track{display:flex;will-change:transform;align-items:stretch;height:100%;padding:.5rem 0;box-sizing:border-box;gap:1rem}'  + '#bannerTrack .banner-item{flex:0 0 auto}'  + '.banner-track.no-anim{width:100%;display:flex}'  + '.banner-track.no-anim{animation:none!important}'  + '@keyframes banner-scroll{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}'  + '.banner-item{display:flex;align-items:stretch;min-width:0;text-decoration:none;color:#fff;transition:background .15s,transform .1s;height:100%;border-radius:var(--r);overflow:hidden}'  + '.banner-item:hover{background:#1a1a1a}'  + '.banner-item.is-active{border:1px solid var(--y);animation:pulse 2s ease-in-out infinite}'  + '.banner-item.is-next{border:1px solid #2a2a2a}';

  // Check if any tur events have geocoded routes (need Leaflet)
  var needsLeaflet = allAvdEvents.some(function(ev) {
    return ev.eventType === "tur" && ev.route && ev.route.days &&
      ev.route.days.some(function(d) {
        return (d.etapper||[]).some(function(e) { return e._lat; });
      });
  });

  // ── HTML ─────────────────────────────────────────────────────────
  var html = '<!DOCTYPE html><html lang="no"><head>'
    + '<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>'
    + '<title>' + escHtml(dept.name) + ' – ' + escHtml(siteName) + '</title>'
    + (needsLeaflet ? '<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>' : '')
    + '<style>' + css + '</style>'
    + (needsLeaflet ? '<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>' : '')
    + '</head><body>'
    + '<div class="header">'
    + '<div class="header-brand" style="position:relative;z-index:2;background:#1a1a1a">'
    + '<div class="header-logo">'+(settings && settings.siteName ? escHtml(settings.siteName.split(' ')[0]) : 'Events')+'</div>'
    + '<div><div class="header-title">' + escHtml(dept.name) + '</div><div class="header-sub">' + escHtml(siteName) + '</div></div>'
    + '</div>'
    + '<div id="bannerSlot" data-cols="' + colCount + '" style="flex:1;overflow:hidden">'
    + '<!-- BANNER -->'
    + (function() {
        // Build banner items: all active first, then upcoming (up to 3)
        var bannerItems = [];
        spotPagaende.forEach(function(ev) { bannerItems.push({ ev: ev, mode: "active" }); });
        var nesteSlice = spotKommende.slice(0, 1); // always exactly 1 next
        nesteSlice.forEach(function(ev) { bannerItems.push({ ev: ev, mode: "next" }); });

        function bannerItem(ev, mode) {
          var isActive = mode === "active";
          var evDate   = new Date(ev.date);
          var timeStr  = ev.date.length > 10 ? evDate.toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"}) : null;
          var endStr   = ev.endTime ? ev.endTime.slice(0,5) : null;
          var url      = "https://" + ev.slug + "." + domain;
          var typeLabel = getTypeLabel(ev.eventType, getSettings());
          var typeCls   = ev.eventType === "kurs" ? "type-kurs" : ev.eventType === "tur" ? "type-tur" : "type-stand";
          // Date column – yellow background on active (same as ev-card dateColLit)
          var dateBg   = isActive ? "background:var(--y)" : "";
          var dayColor = isActive ? "color:#111" : "";
          var monColor = isActive ? "color:#111;opacity:.8" : "";
          var arrColor = isActive ? "color:var(--y)" : "";
          return '<a href="' + escHtml(url) + '" class="ev-card banner-item ' + (isActive ? "active is-active" : "is-next") + '">'
            + '<div class="ev-date-col" ' + (isActive ? 'style="' + dateBg + '"' : '') + '>'
            +   '<div class="ev-day" ' + (isActive ? 'style="' + dayColor + '"' : '') + '>' + evDate.getDate() + '</div>'
            +   '<div class="ev-month" ' + (isActive ? 'style="' + monColor + '"' : '') + '>'
            +     evDate.toLocaleDateString("en-GB",{month:"short"})
            +   '</div>'
            + '</div>'
            + '<div class="ev-body" style="flex:1;min-width:0">'
            +   '<div class="ev-top">'
            +     '<span class="type-badge ' + typeCls + '">' + typeLabel + '</span>'
            +     (isActive ? '<span class="active-badge">Pågående nå</span>' : '<span class="today-badge">Kommende</span>')
            +   '</div>'
            +   '<div class="ev-title">' + escHtml(ev.title) + '</div>'
            +   (timeStr ? '<div class="ev-meta">🕐 ' + timeStr + (endStr ? '–'+endStr : '') + '</div>' : '')
            +   (ev.location ? '<div class="ev-meta">📍 ' + escHtml(ev.location) + '</div>' : '')
            + '</div>'
            + '<div class="ev-arrow" ' + (isActive ? 'style="' + arrColor + '"' : '') + '>→</div>'
            + '</a>';
        }

        // No active events – show dimmed placeholder + next event
        if (bannerItems.length === 0) {
          var emptyItem = '<a href="#" class="ev-card banner-item is-next" style="opacity:.4;cursor:default;pointer-events:none">'
            + '<div class="ev-date-col" style="background:#1a1a1a">'
            + '<div style="font-size:1.6rem;line-height:1;color:#444">–</div>'
            + '</div>'
            + '<div class="ev-body" style="flex:1;min-width:0;display:flex;align-items:center">'
            + '<div style="font-size:.82rem;color:#555;font-style:italic">Ingen pågående aktivitet</div>'
            + '</div>'
            + '</a>';
          var nextItem = spotNeste ? bannerItem(spotNeste, 'next') : '';
          var trackHtml = '<div class="banner-track no-anim">' + emptyItem + nextItem + '</div>';
          return '<style>.banner-item{flex:1 1 0;min-width:0}</style>'
            + '<div class="banner-wrap" id="bannerWrap">'
            + trackHtml
            + '</div>';
        }

        var itemsHtml = bannerItems.map(function(b){ return bannerItem(b.ev, b.mode); }).join("");

        // If only 1 item, no scroll needed
        var needsScroll = spotPagaende.length >= 2;
        var trackStyle = needsScroll
          ? 'class="banner-track" id="bannerTrack"'
          : 'class="banner-track no-anim"';

        // Duplicate items for seamless loop when scrolling
        var trackContent = needsScroll ? (itemsHtml + itemsHtml) : itemsHtml;

        return '<div class="banner-wrap" id="bannerWrap">'
          + '<div ' + trackStyle + '>' + trackContent + '</div>'
          + '</div>'
          + '<style>.banner-item{flex:1 1 0;min-width:0}</style>'
          + (needsScroll ? '<script>'
            + '(function(){'
            + 'var wrap=document.getElementById("bannerWrap");'
            + 'var track=document.getElementById("bannerTrack");'
            + 'if(!wrap||!track)return;'
            + 'var items=track.querySelectorAll(".banner-item");'
            + 'var half=Math.floor(items.length/2);'
            + 'var itemW=items[0]?items[0].getBoundingClientRect().width:300;'
            + 'var totalW=(itemW+16)*half;'
            + 'var dur=Math.max(8,half*6);'
            // Pause on hover
            + 'var paused=false;'
            + 'var pos=0;var last=null;'
            + 'function step(ts){'
            + '  if(!last)last=ts;'
            + '  if(!paused)pos+=(ts-last)/1000*(totalW/dur);'
            + '  if(pos>=totalW)pos-=totalW;'
            + '  track.style.transform="translateX(-"+pos.toFixed(2)+"px)";'
            + '  last=ts;'
            + '  requestAnimationFrame(step);'
            + '}'
            + 'wrap.addEventListener("mouseenter",function(){paused=true;});'
            + 'wrap.addEventListener("mouseleave",function(){paused=false;last=null;});'
            + 'requestAnimationFrame(step);'
            + '})();'
            + '<\/script>' : '');
      })()
    + '</div>'   // close banner slot
    + '</div>'   // close header
    + '<div class="container">';

  if (filtered.length === 0) {
    html += '<div style="text-align:center;padding:4rem 1rem;color:#444">'
      + '<div style="font-size:2.5rem;margin-bottom:.75rem">📅</div>'
      + '<p>Ingen kommende arrangementer</p></div>';
  } else {
    html += '<div class="cols">';
    columns.forEach(function(kol) {
      var tidligere = kol.events.filter(function(ev) { return ev.date && getEndMs(ev) < now; });
      var pagaende  = kol.events.filter(function(ev) { return ev.date && new Date(ev.date).getTime() <= now && getEndMs(ev) >= now; });
      var kommende  = kol.events.filter(function(ev) { return !ev.date || new Date(ev.date).getTime() > now; });

      function byDate(a,b) {
        if (!a.date && !b.date) return 0;
        if (!a.date) return -1;
        if (!b.date) return 1;
        return new Date(a.date) - new Date(b.date);
      }
      tidligere.sort(byDate);
      pagaende.sort(byDate);
      kommende.sort(byDate);

      var kommendeCount = pagaende.length + kommende.length;
      html += '<div>'
        + '<div class="col-head"><h2>' + escHtml(kol.label) + '</h2>'
        + '<span class="col-count">' + kommendeCount + ' kommende</span></div>';

      if (tidligere.length === 0 && pagaende.length === 0 && kommende.length === 0) {
        html += '<div class="empty-col">Ingen arrangementer</div>';
      }
      if (tidligere.length > 0) {
        html += '<div style="font-size:.68rem;text-transform:uppercase;letter-spacing:.8px;color:#444;margin:.75rem 0 .4rem;border-bottom:1px solid #222;padding-bottom:.3rem">Tidligere</div>';
        tidligere.forEach(function(ev) { html += evCard(ev); });
      }
      if (pagaende.length > 0) {
        html += '<div style="font-size:.68rem;text-transform:uppercase;letter-spacing:.8px;color:#888;margin:.75rem 0 .4rem;border-bottom:1px solid #333;padding-bottom:.3rem">Pågående nå</div>';
        pagaende.forEach(function(ev) { html += evCard(ev); });
      }
      if (kommende.length > 0) {
        if (pagaende.length > 0 || tidligere.length > 0) {
          html += '<div style="font-size:.68rem;text-transform:uppercase;letter-spacing:.8px;color:#444;margin:.75rem 0 .4rem;border-bottom:1px solid #222;padding-bottom:.3rem">Kommende</div>';
        }
        kommende.forEach(function(ev) { html += evCard(ev); });
      }
      html += '</div>';
    });
    html += '</div>';
  }

  html += '</div><footer>' + escHtml(siteName) + ' · ' + escHtml(dept.name) + '</footer>'
    + '<script>\n'
    + '(function(){\n'
    // SSE: koble til og reload ved events_updated for denne avdelingen
    + '  var DEPT_ID = ' + JSON.stringify(dept.id) + ';\n'
    + '  var es;\n'
    + '  function connect() {\n'
    + '    es = new EventSource("/api/events/stream?department=" + DEPT_ID);\n'
    + '    es.onmessage = function(e) {\n'
    + '      try {\n'
    + '        var msg = JSON.parse(e.data);\n'
    + '        if (msg.type === "events_updated") location.reload();\n'
    + '      } catch(err) {}\n'
    + '    };\n'
    + '    es.onerror = function() {\n'
    + '      es.close();\n'
    + '      setTimeout(connect, 5000);\n'
    + '    };\n'
    + '  }\n'
    + '  connect();\n'
    // Reload ved visibility (komme tilbake fra bakgrunn med eventuell statusendring)
    + '  var EVENTS = ' + JSON.stringify(allAvdEvents.map(function(ev) {
        return { start: new Date(ev.date).getTime(), end: (function() {
          if (ev.endDate) { var d=new Date(ev.endDate); if(ev.endTime){var p=ev.endTime.split(":");d.setHours(+p[0],+p[1],0,0);} else d.setHours(23,59,59,999); return d.getTime(); }
          var d2=new Date(ev.date); if(ev.endTime){var p2=ev.endTime.split(":");d2.setHours(+p2[0],+p2[1],0,0);} else d2.setHours(23,59,59,999); return d2.getTime();
        })() };
      })) + ';\n'
    + '  function statusOf(ev, now) { if(now<ev.start)return"neste"; if(now<=ev.end)return"pagaende"; return"tidligere"; }\n'
    + '  var lastStatuses = EVENTS.map(function(ev){return statusOf(ev,Date.now());});\n'
    + '  // Sjekk hvert minutt om et event har skiftet status basert på klokken\n'
    + '  setInterval(function() {\n'
    + '    var now = Date.now();\n'
    + '    var changed = EVENTS.some(function(ev,i){return statusOf(ev,now)!==lastStatuses[i];});\n'
    + '    if (changed) location.reload();\n'
    + '  }, 60000);\n'
    + '  document.addEventListener("visibilitychange", function() {\n'
    + '    if (document.visibilityState === "visible") {\n'
    + '      var now = Date.now();\n'
    + '      var changed = EVENTS.some(function(ev,i){return statusOf(ev,now)!==lastStatuses[i];});\n'
    + '      if (changed) { location.reload(); return; }\n'
    + '      if (!es || es.readyState === 2) connect();\n'  // reconnect om SSE er stengt
    + '    }\n'
    + '  });\n'
    + '})();\n'
    + '<\/script>\n'
    + '</body></html>';
  res.send(html);
}

// ── Public event page ────────────────────────────────────────────
function serveEventPage(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.slug === req.eventSlug; });
  if (!ev) return res.status(404).send(notFoundPage(req.eventSlug));

  // Sjekk om eventet er merket som offentlig
  // Ikke-offentlige events krever at bruker er innlogget i admin (session)
  if (!ev.isPublic && !req.session.user) {
    return res.status(401).send(authWallPage(ev));
  }

  const isAuthenticated = !!req.session.user;
  res.send(buildEventPage(ev, isAuthenticated));
}

function authWallPage(ev) {
  var title = ev ? escHtml(ev.title) : "Arrangement";
  return '<!DOCTYPE html><html lang="no"><head><meta charset="UTF-8"/>'
    + '<meta name="viewport" content="width=device-width,initial-scale=1"/>'
    + '<title>' + title + ' – Krever innlogging</title>'
    + '<style>body{font-family:"Helvetica Neue",Arial,sans-serif;background:#1a1a1a;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem}'
    + '.box{max-width:400px;width:100%;text-align:center}'
    + '.logo{background:#FFD100;color:#111;font-weight:900;font-size:1.4rem;padding:6px 14px;border-radius:6px;display:inline-block;margin-bottom:1.5rem}'
    + 'h1{font-size:1.4rem;margin-bottom:.5rem}'
    + 'p{color:#888;font-size:.9rem;margin-bottom:1.5rem;line-height:1.6}'
    + '.btn{display:inline-block;background:#FFD100;color:#111;font-weight:700;padding:.75rem 2rem;border-radius:6px;text-decoration:none;font-size:1rem}'
    + '</style></head><body>'
    + '<div class="box">'
    + '<div class="logo">'+(s ? escHtml((s.siteName||'Events').split(' ')[0]) : 'Events')+'</div>'
    + '<h1>' + title + '</h1>'
    + '<p>Dette arrangementet er ikke offentlig tilgjengelig.<br>Logg inn med din NAF-konto for å se siden.</p>'
    + '<a href="https://' + escHtml(ADMIN_DOMAIN) + '" class="btn">🔒 Logg inn</a>'
    + '</div></body></html>';
}

function notFoundPage(slug) {
  return '<!DOCTYPE html><html><head><title>Ikke funnet</title>'
    + '<style>body{font-family:sans-serif;text-align:center;padding:5rem;background:#1a1a1a;color:#fff}'
    + 'h1{color:#FFD100}a{color:#FFD100}</style></head>'
    + '<body><h1>'+(getSettings().siteName||'Events Admin')+'</h1><p>Finner ikke eventet <strong>' + escHtml(slug) + '</strong>.</p>'
    + '<a href="https://' + escHtml(ADMIN_DOMAIN) + '">← Back</a></body></html>';
}

function buildEventPage(ev, isAuthenticated) {
  return ev.eventType === "mote"  ? buildMotePage(ev, isAuthenticated)
       : ev.eventType === "kurs"  ? buildKursPage(ev, isAuthenticated)
       : ev.eventType === "tur"   ? buildTurPage(ev, isAuthenticated)
       :                            buildStandPage(ev, isAuthenticated);
}


// ── Shared helpers ────────────────────────────────────────────────

function evFmtDate(d) {
  if (!d) return '';
  return new Date(d).toLocaleDateString('nb-NO', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
}
function evFmtTime(d) {
  if (!d) return '';
  return new Date(d).toLocaleTimeString('nb-NO', { hour:'2-digit', minute:'2-digit' });
}

function tabletCSS(accentColor) {
  const y = accentColor || '#FFD100';
  return `<style>
:root{--y:${y};--yd:color-mix(in srgb,${y} 70%,#000);--b:#111;--g:#1c1c1c;--g2:#252525;--g3:#333;--red:#E2001A;--text:#f0f0f0;--text2:#aaa}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html{font-size:18px}
body{font-family:"Helvetica Neue",Arial,sans-serif;background:var(--b);color:var(--text);min-height:100vh;display:flex;flex-direction:column;overscroll-behavior:none}
/* Header */
.ev-header{background:var(--g);border-bottom:4px solid var(--y);padding:.75rem 1.25rem;display:flex;align-items:center;gap:.75rem;position:sticky;top:0;z-index:100}
.ev-logo{background:var(--y);color:#111;font-weight:900;font-size:1rem;padding:4px 10px;border-radius:5px;white-space:nowrap}
.ev-org{font-size:.85rem;color:var(--text2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.staff-btn{background:none;border:1px solid var(--g3);color:var(--text2);border-radius:6px;padding:7px 14px;font-size:.82rem;font-weight:600;cursor:pointer;white-space:nowrap;min-height:44px}
.staff-btn:active{background:var(--g2)}
/* Hero */
.ev-hero{position:relative;min-height:200px;background:var(--g2);display:flex;flex-direction:column;justify-content:flex-end}
.ev-hero img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;opacity:.45}
.ev-hero-content{position:relative;padding:1.5rem 1.25rem 1.25rem;background:linear-gradient(transparent,rgba(0,0,0,.9) 40%)}
.ev-type-badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.5px;margin-bottom:.6rem}
.badge-mote{background:#3a2a0a;color:#f5c500;border:1px solid #6a4a14}
.badge-kurs{background:#0d2035;color:#7dc8ff;border:1px solid #1a4a70}
.badge-tur{background:#1e0d35;color:#d8b4fe;border:1px solid #4a2a7a}
.badge-stand{background:#0d2a0d;color:#7dff7d;border:1px solid #1a5a1a}
.ev-title{font-size:1.7rem;font-weight:900;line-height:1.15;color:#fff}
.ev-meta{display:flex;flex-wrap:wrap;gap:.6rem 1.5rem;margin-top:.6rem;font-size:.88rem;color:#ccc}
.ev-meta span{display:flex;align-items:center;gap:.3rem}
/* Nav tabs */
.ev-tabs{display:flex;background:var(--g);border-bottom:1px solid var(--g3);overflow-x:auto;scrollbar-width:none;position:sticky;top:56px;z-index:90}
.ev-tabs::-webkit-scrollbar{display:none}
.ev-tab{padding:1rem 1.25rem;font-size:.88rem;font-weight:700;color:var(--text2);border-bottom:3px solid transparent;white-space:nowrap;cursor:pointer;min-height:52px;display:flex;align-items:center;gap:.35rem;flex-shrink:0;transition:color .15s}
.ev-tab.active{color:var(--y);border-bottom-color:var(--y)}
.ev-tab:active{background:var(--g2)}
/* Content */
.ev-content{flex:1;padding:1.25rem}
.ev-panel{display:none}
.ev-panel.active{display:block}
/* Cards */
.ev-card{background:var(--g);border-radius:10px;padding:1.25rem;margin-bottom:1rem;border:1px solid var(--g3)}
.ev-card-title{font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.6px;color:var(--y);margin-bottom:.75rem;padding-bottom:.5rem;border-bottom:1px solid var(--g3)}
/* Info rows */
.info-row{display:flex;gap:.75rem;align-items:flex-start;padding:.6rem 0;border-bottom:1px solid var(--g3)}
.info-row:last-child{border-bottom:none}
.info-row .icon{font-size:1.25rem;flex-shrink:0;margin-top:.1rem}
.info-row .label{font-size:.75rem;color:var(--text2);margin-bottom:.15rem}
.info-row .value{font-size:.95rem;color:var(--text);line-height:1.5}
/* Form */
.ev-form label{display:block;font-size:.78rem;color:var(--text2);margin-bottom:.3rem;margin-top:.75rem;font-weight:600}
.ev-form label:first-child{margin-top:0}
.ev-form input,.ev-form textarea,.ev-form select{width:100%;padding:14px;background:var(--g2);border:2px solid var(--g3);border-radius:8px;color:var(--text);font-size:1rem;font-family:inherit;transition:border-color .15s}
.ev-form input:focus,.ev-form textarea:focus,.ev-form select:focus{outline:none;border-color:var(--y)}
.ev-form textarea{min-height:100px;resize:vertical}
/* Buttons */
.btn-primary{width:100%;padding:16px;background:var(--y);color:#111;font-weight:900;font-size:1.05rem;border:none;border-radius:8px;cursor:pointer;margin-top:1rem;min-height:56px;transition:filter .15s}
.btn-primary:active{filter:brightness(.9)}
.btn-primary:disabled{opacity:.5;cursor:default}
.btn-secondary{width:100%;padding:14px;background:none;color:var(--text);font-weight:700;font-size:1rem;border:2px solid var(--g3);border-radius:8px;cursor:pointer;margin-top:.6rem;min-height:52px}
.btn-secondary:active{background:var(--g2)}
/* Messages */
.msg{padding:1rem;border-radius:8px;font-size:.92rem;margin:.75rem 0;line-height:1.5}
.msg-ok{background:#0d2a0d;border:1px solid #2d6a2d;color:#7dff7d}
.msg-err{background:#2a0d0d;border:1px solid #6a2d2d;color:#ff7d7d}
.msg-info{background:#0d1a2a;border:1px solid #1a4a6a;color:#7dc8ff}
/* Spots / count */
.spots-bar{background:var(--g2);border-radius:6px;padding:.75rem 1rem;margin-bottom:1rem;display:flex;justify-content:space-between;align-items:center;font-size:.88rem}
.spots-full{color:var(--red);font-weight:700}
.spots-ok{color:#7dff7d;font-weight:700}
.spots-low{color:var(--y);font-weight:700}
/* Reg list */
.reg-list{display:flex;flex-direction:column;gap:.4rem}
.reg-item{display:flex;align-items:center;justify-content:space-between;background:var(--g2);border-radius:8px;padding:.9rem 1rem;min-height:56px}
.reg-name{font-weight:700;font-size:.95rem}
.reg-meta{font-size:.78rem;color:var(--text2);margin-top:.15rem}
.checkin-done{color:#7dff7d;font-size:.85rem;font-weight:700}
.checkin-btn{background:var(--y);color:#111;border:none;border-radius:6px;padding:9px 18px;font-size:.88rem;font-weight:800;cursor:pointer;min-height:44px}
.checkin-btn:active{filter:brightness(.9)}
/* Search */
.search-wrap{position:relative;margin-bottom:1rem}
.search-wrap input{padding-left:2.5rem}
.search-icon{position:absolute;left:.85rem;top:50%;transform:translateY(-50%);font-size:1rem;pointer-events:none}
/* Staff */
.staff-list{display:flex;flex-direction:column;gap:.4rem}
.staff-item{display:flex;align-items:center;justify-content:space-between;background:var(--g2);border-radius:8px;padding:.9rem 1rem;min-height:56px}
.staff-name{font-weight:700}
.staff-role{font-size:.78rem;color:var(--text2)}
/* Guestbook */
.gb-entry{background:var(--g2);border-radius:10px;padding:1rem;margin-bottom:.75rem;border-left:4px solid var(--y)}
.gb-name{font-weight:800;color:var(--y);font-size:.95rem;margin-bottom:.3rem}
.gb-msg{font-size:.92rem;color:#ddd;line-height:1.6}
.gb-date{font-size:.72rem;color:var(--text2);margin-top:.4rem}
/* PIN overlay */
.pin-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:200;align-items:flex-end;justify-content:center}
.pin-overlay.open{display:flex}
.pin-sheet{background:var(--g);border-radius:20px 20px 0 0;width:100%;max-width:540px;padding:1.5rem;padding-bottom:calc(1.5rem + env(safe-area-inset-bottom))}
.pin-sheet h3{font-size:1.1rem;font-weight:800;margin-bottom:1rem;text-align:center}
.pin-close-btn{position:absolute;top:1rem;right:1rem;background:none;border:none;font-size:1.5rem;color:var(--text2);cursor:pointer;padding:4px 10px}
/* Etappe list */
.etappe-item{background:var(--g2);border-radius:8px;padding:1rem;margin-bottom:.6rem;border-left:4px solid var(--y)}
.etappe-num{font-size:.72rem;color:var(--text2);font-weight:700;text-transform:uppercase;margin-bottom:.2rem}
.etappe-name{font-weight:800;font-size:1rem}
.etappe-meta{font-size:.82rem;color:var(--text2);margin-top:.3rem;display:flex;gap:1rem;flex-wrap:wrap}
/* Lottery */
.lottery-box{background:linear-gradient(135deg,#1a0a2e,#0d1a0d);border:2px solid var(--y);border-radius:12px;padding:2rem;text-align:center}
.lottery-drum{font-size:4.5rem;display:block;margin:.5rem 0}
.lottery-drum.spin{animation:drum .07s linear infinite}
@keyframes drum{0%{transform:rotateY(0)}100%{transform:rotateY(360deg)}}
.winner-pop{background:#0d2a0d;border:2px solid #4ade80;border-radius:10px;padding:1.25rem;margin:1rem 0;animation:wpop .4s cubic-bezier(.175,.885,.32,1.275)}
@keyframes wpop{0%{transform:scale(.7);opacity:0}100%{transform:scale(1);opacity:1}}
.winner-name{font-size:1.6rem;font-weight:900;color:#4ade80}
.past-winner{display:flex;justify-content:space-between;background:#0d0d0d;border-radius:6px;padding:.6rem .9rem;margin-bottom:.3rem;font-size:.88rem}
/* Offline stripe */
.ev-header.offline{border-bottom:none;position:relative}
.ev-header.offline::after{content:"";position:absolute;bottom:0;left:0;right:0;height:4px;background:repeating-linear-gradient(90deg,var(--y) 0,var(--y) 12px,var(--red) 12px,var(--red) 24px);background-size:24px 4px;animation:stripe .5s linear infinite}
@keyframes stripe{to{background-position:24px 0}}
/* Floating Personal-knapp – vises ved bunn */
.staff-fab{position:fixed;bottom:1.5rem;right:1.5rem;z-index:150;display:flex;flex-direction:column;align-items:center;gap:.3rem;pointer-events:none}
.staff-fab-btn{background:var(--y);color:#111;border:none;border-radius:50px;padding:14px 22px;font-size:.95rem;font-weight:900;cursor:pointer;display:flex;align-items:center;gap:.5rem;box-shadow:0 4px 20px rgba(0,0,0,.5);pointer-events:all;transform:translateY(120px);opacity:0;transition:transform .4s cubic-bezier(.175,.885,.32,1.275),opacity .3s ease}
.staff-fab-btn.visible{transform:translateY(0);opacity:1}
.staff-fab-btn.bounce{animation:fab-bounce .6s cubic-bezier(.175,.885,.32,1.275)}
@keyframes fab-bounce{0%{transform:translateY(0)}30%{transform:translateY(-12px)}60%{transform:translateY(-4px)}100%{transform:translateY(0)}}
.staff-fab-hint{font-size:.7rem;color:var(--text2);opacity:0;transition:opacity .3s;pointer-events:none;text-align:center;background:var(--g);padding:3px 10px;border-radius:10px;white-space:nowrap}
.staff-fab-btn.visible ~ .staff-fab-hint{opacity:1}
/* Empty state */
.empty{text-align:center;padding:2.5rem 1rem;color:var(--text2);font-size:.92rem}
.empty-icon{font-size:2.5rem;display:block;margin-bottom:.6rem}
/* GDPR note */
.gdpr-note{font-size:.75rem;color:var(--text2);line-height:1.6;margin-top:.75rem;padding:.75rem;background:var(--g2);border-radius:6px}
</style>`;
}

function tabletHeader(ev, settings, typeClass, typeLabel) {
  const siteName = escHtml(settings.siteName || 'Events Admin');
  const logoUrl  = settings.logoUrl || '';
  return `<header class="ev-header" id="evHeader">
  ${logoUrl
    ? `<img src="${escHtml(logoUrl)}" style="height:32px;object-fit:contain;border-radius:3px" alt="${siteName}"/>`
    : `<div class="ev-logo">${siteName}</div>`}
  <div class="ev-org">${siteName}</div>
</header>`;
}

function tabletHero(ev, typeClass, typeLabel) {
  const title   = escHtml(ev.title || '');
  const loc     = ev.location ? escHtml(ev.location) : '';
  const dateStr = ev.date ? evFmtDate(ev.date) : '';
  const timeStr = ev.date ? evFmtTime(ev.date) : '';
  const imgTag  = ev.image
    ? `<img src="${escHtml(ev.image)}" alt="${title}"/>`
    : '';
  return `<div class="ev-hero">
  ${imgTag}
  <div class="ev-hero-content">
    <div class="ev-type-badge ${typeClass}">${typeLabel}</div>
    <h1 class="ev-title">${title}</h1>
    <div class="ev-meta">
      ${dateStr ? `<span>📅 ${dateStr}${timeStr ? ' kl. ' + timeStr : ''}</span>` : ''}
      ${loc     ? `<span>📍 ${loc}</span>` : ''}
    </div>
  </div>
</div>`;
}

function tabletPinSheet(ev) {
  const hasPin = !!ev.staffPin;
  const settings = getSettings();
  const depts    = settings.departments || [];
  const staff    = ev.staff || [];

  const staffRows = staff.length
    ? staff.map(function(s) {
        return `<div class="staff-item" id="si-${escHtml(s.id)}" data-name="${escHtml((s.name||'').toLowerCase())}">
          <div>
            <div class="staff-name">${escHtml(s.name)}</div>
            ${s.role ? `<div class="staff-role">${escHtml(s.role)}</div>` : ''}
          </div>
          ${s.checkedIn
            ? `<span class="checkin-done">✔ ${new Date(s.checkedInAt||Date.now()).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})}</span>`
            : `<button class="checkin-btn" onclick="staffCheckIn('${escHtml(s.id)}')">Sjekk inn</button>`}
        </div>`;
      }).join('')
    : `<div class="empty"><span class="empty-icon">👔</span>Ingen forhåndsregistrert personell</div>`;

  const deptSel = depts.length
    ? `<label>Avdeling</label>
       <select id="sDept" class="ev-form">
         <option value="">– Velg –</option>
         ${depts.map(d => `<option>${escHtml(d.name)}</option>`).join('')}
       </select>`
    : '';

  return `
<!-- PIN sheet -->
<div class="pin-overlay" id="pinOverlay">
  <div class="pin-sheet" style="position:relative">
    <button class="pin-close-btn" onclick="closePinSheet()">×</button>
    <h3>🔐 Personalinngang</h3>
    ${hasPin
      ? `<div id="pinErr"></div>
         <div class="ev-form">
           <label>PIN-kode</label>
           <input type="password" id="pinInput" inputmode="numeric" pattern="[0-9]*" maxlength="10" placeholder="••••" autocomplete="off" style="text-align:center;font-size:1.5rem;letter-spacing:.5rem"/>
         </div>
         <button class="btn-primary" onclick="verifyPin()">Bekreft →</button>`
      : `<button class="btn-primary" onclick="unlockStaff()">Gå til innsjekk →</button>`}
  </div>
</div>

<!-- Staff sheet -->
<div class="pin-overlay" id="staffOverlay">
  <div class="pin-sheet" style="position:relative;max-height:85vh;overflow-y:auto">
    <button class="pin-close-btn" onclick="closeStaffSheet()">×</button>
    <h3>👔 Personal – innsjekk</h3>
    ${staff.length ? `<div class="search-wrap ev-form" style="margin-bottom:1rem"><span class="search-icon">🔍</span><input type="search" id="staffSearch" placeholder="Søk etter navn…" oninput="filterStaff(this.value)" style="padding-left:2.5rem"/></div>` : ''}
    <div class="staff-list" id="staffList">${staffRows}</div>
    <hr style="border-color:#333;margin:1.25rem 0"/>
    <div style="font-size:.72rem;font-weight:800;color:var(--y);text-transform:uppercase;letter-spacing:.5px;margin-bottom:.75rem">Ikke på listen?</div>
    <div id="staffMsg"></div>
    <div class="ev-form">
      <label>Navn *</label>
      <input id="sName" type="text" placeholder="Ditt navn" autocomplete="name"/>
      <label>Rolle / funksjon</label>
      <input id="sRole" type="text" placeholder="Vakt, guide, teknikk…"/>
      ${deptSel}
    </div>
    <button class="btn-primary" onclick="selfCheckIn()" style="margin-top:.75rem">Registrer meg som personell</button>
  </div>
</div>`;
}

function tabletSharedJS(ev) {
  const hasPin = !!ev.staffPin;
  return `<script>
var EV_ID="${ev.id}";
var EV_SLUG="${escHtml(ev.slug)}";
var PHOTO_BASE_URL="https://${ADMIN_DOMAIN}";

// Tabs
function showTab(id) {
  document.querySelectorAll('.ev-panel').forEach(function(p){p.classList.remove('active')});
  document.querySelectorAll('.ev-tab').forEach(function(t){t.classList.remove('active')});
  var panel = document.getElementById('tab-'+id);
  var tab   = document.querySelector('[data-tab="'+id+'"]');
  if(panel) panel.classList.add('active');
  if(tab)   tab.classList.add('active');
  // Scroll tabs into view
  if(tab) tab.scrollIntoView({behavior:'smooth',block:'nearest',inline:'center'});
}

// PIN sheet
function openPinSheet(){document.getElementById('pinOverlay').classList.add('open')}
function closePinSheet(){document.getElementById('pinOverlay').classList.remove('open')}
function closeStaffSheet(){document.getElementById('staffOverlay').classList.remove('open')}

${hasPin ? `
async function verifyPin(){
  var p=document.getElementById('pinInput').value.trim();
  var err=document.getElementById('pinErr');
  if(!p){if(err)err.innerHTML='<div class="msg msg-err">Skriv inn PIN</div>';return;}
  var r=await fetch('/api/events/'+EV_ID+'/verify-pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:p})});
  var d=await r.json();
  if(d.ok){closePinSheet();document.getElementById('staffOverlay').classList.add('open');}
  else{if(err)err.innerHTML='<div class="msg msg-err">Feil PIN-kode</div>';}
}` : `
function unlockStaff(){closePinSheet();document.getElementById('staffOverlay').classList.add('open');}`}

async function staffCheckIn(id){
  var btn=document.querySelector('#si-'+id+' .checkin-btn');
  if(btn){btn.disabled=true;btn.textContent='...';}
  var r=await fetch('/api/events/'+EV_ID+'/registrations/'+id+'/checkin',{method:'POST',headers:{'Content-Type':'application/json'}});
  if(r.ok){
    var t=new Date().toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'});
    var item=document.getElementById('si-'+id);
    if(item){var old=item.querySelector('.checkin-btn');if(old){var sp=document.createElement('span');sp.className='checkin-done';sp.textContent='✔ '+t;old.replaceWith(sp);}}
  }
}

async function selfCheckIn(){
  var name=document.getElementById('sName').value.trim();
  var role=document.getElementById('sRole')?.value.trim()||'';
  var dept=document.getElementById('sDept')?.value||'';
  var msg=document.getElementById('staffMsg');
  if(!name){if(msg)msg.innerHTML='<div class="msg msg-err">Navn er påkrevd</div>';return;}
  var r=await fetch('/api/events/'+EV_ID+'/staff',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,role,department:dept,walkin:true})});
  var d=await r.json();
  if(r.ok){
    if(msg)msg.innerHTML='<div class="msg msg-ok">✅ Registrert! Velkommen, '+esc(name)+'</div>';
    document.getElementById('sName').value='';
    document.getElementById('sRole').value='';
  } else {
    if(msg)msg.innerHTML='<div class="msg msg-err">'+esc(d.err||d.error||'Feil')+'</div>';
  }
}

function filterStaff(q){
  q=q.toLowerCase();
  document.querySelectorAll('#staffList .staff-item').forEach(function(el){
    el.style.display=(!q||el.dataset.name.includes(q))?'flex':'none';
  });
}

function esc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}

// Offline indicator
window.addEventListener('online',function(){document.getElementById('evHeader').classList.remove('offline')});
window.addEventListener('offline',function(){document.getElementById('evHeader').classList.add('offline')});

// Floating Personal-knapp: vises når man er 80% ned på siden
(function(){
  var fab = document.getElementById('staffFab');
  if(!fab) return;
  var shown = false;
  var bounced = false;
  function checkScroll(){
    var scrolled = window.scrollY + window.innerHeight;
    var total = document.body.scrollHeight;
    var pct = scrolled / total;
    if(pct > 0.75 && !shown){
      shown = true;
      fab.classList.add('visible');
      if(!bounced){
        bounced = true;
        setTimeout(function(){
          fab.classList.add('bounce');
          setTimeout(function(){ fab.classList.remove('bounce'); }, 700);
        }, 450);
      }
    } else if(pct < 0.6 && shown) {
      shown = false;
      fab.classList.remove('visible');
    }
  }
  window.addEventListener('scroll', checkScroll, {passive:true});
  // Kort innhold: vis direkte
  setTimeout(function(){
    if(document.body.scrollHeight <= window.innerHeight + 50){
      shown = true;
      fab.classList.add('visible');
      setTimeout(function(){
        if(!bounced){ bounced=true; fab.classList.add('bounce'); setTimeout(function(){fab.classList.remove('bounce');},700); }
      }, 800);
    }
  }, 500);
})();
<\/script>`;
}

// ── Stand page ────────────────────────────────────────────────────
function buildStandPage(ev, isAuthenticated) {
  const settings      = getSettings();
  const regs          = ev.registrations || [];
  const lottery       = ev.lottery || null;
  const lotteryOn     = lottery && lottery.enabled;
  const gb            = (ev.guestbook || []).filter(function(g){ return g.approved; });
  const contactEmail  = settings.contactEmail || '';
  const siteName      = escHtml(settings.siteName || 'Events Admin');
  const accentColor   = (settings.colors && settings.colors.accent) || '#FFD100';

  const gbHtml = gb.length
    ? gb.map(function(g){
        return `<div class="gb-entry">
          <div class="gb-name">${escHtml(g.name)}</div>
          <div class="gb-msg">${escHtml(g.message).replace(/\n/g,'<br>')}</div>
          <div class="gb-date">${new Date(g.createdAt).toLocaleDateString('nb-NO',{day:'numeric',month:'long',year:'numeric'})}</div>
        </div>`;
      }).join('')
    : '<div class="empty"><span class="empty-icon">✍️</span>Ingen kommentarer ennå – vær den første!</div>';

  return `<!DOCTYPE html>
<html lang="no">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escHtml(ev.title)} – ${siteName}</title>
${tabletCSS(accentColor)}
</head>
<body>
${tabletHeader(ev, settings, 'badge-stand', '🟢 ' + getTypeLabel('stand', settings))}
${tabletHero(ev, 'badge-stand', '🟢 ' + getTypeLabel('stand', settings))}

<!-- Tabs -->
<nav class="ev-tabs">
  <div class="ev-tab active" data-tab="info" onclick="showTab('info')">ℹ️ Om standen</div>
  <div class="ev-tab" data-tab="reg" onclick="showTab('reg')">📧 Hold meg oppdatert</div>
  ${lotteryOn ? `<div class="ev-tab" data-tab="lottery" onclick="showTab('lottery')">🎰 Lotteri</div>` : ''}
  <div class="ev-tab" data-tab="gb" onclick="showTab('gb')">✍️ Gjestebok</div>
</nav>

<div class="ev-content">

  <!-- Info -->
  <div class="ev-panel active" id="tab-info">
    ${ev.description ? `<div class="ev-card"><div class="ev-card-title">Om standen</div><p style="line-height:1.7;color:#ddd">${escHtml(ev.description).replace(/\n/g,'<br>')}</p></div>` : ''}
    <div class="ev-card">
      <div class="ev-card-title">Praktisk info</div>
      ${ev.date ? `<div class="info-row"><span class="icon">📅</span><div><div class="label">Dato og tid</div><div class="value">${evFmtDate(ev.date)}${ev.date ? ' kl. ' + evFmtTime(ev.date) : ''}</div></div></div>` : ''}
      ${ev.location ? `<div class="info-row"><span class="icon">📍</span><div><div class="label">Sted</div><div class="value">${escHtml(ev.location)}</div></div></div>` : ''}
      ${contactEmail ? `<div class="info-row"><span class="icon">✉️</span><div><div class="label">Kontakt</div><div class="value"><a href="mailto:${escHtml(contactEmail)}" style="color:var(--y)">${escHtml(contactEmail)}</a></div></div></div>` : ''}
    </div>
    <button class="btn-primary" onclick="showTab('reg')">📧 Meld meg på e-postlisten →</button>
  </div>

  <!-- Registrering -->
  <div class="ev-panel" id="tab-reg">
    <div class="ev-card">
      <div class="ev-card-title">📧 Hold deg oppdatert</div>
      <p style="color:#bbb;font-size:.92rem;margin-bottom:1.25rem;line-height:1.6">
        ${lotteryOn
          ? 'Meld deg på og motta informasjon – og delta automatisk i <strong style="color:var(--y)">lodtrekningen</strong>!'
          : 'Meld deg på og motta informasjon vi deler fra denne standen direkte på e-post.'}
      </p>
      <div id="regMsg"></div>
      <div class="ev-form">
        <label>Navn *</label>
        <input id="rName" type="text" placeholder="Ditt fulle navn" autocomplete="name"/>
        <label>E-post *</label>
        <input id="rEmail" type="email" placeholder="din@epost.no" autocomplete="email"/>
        <label>Telefon <span style="color:#666;font-weight:400">(valgfritt)</span></label>
        <input id="rPhone" type="tel" placeholder="+47 000 00 000" autocomplete="tel"/>
      </div>
      <button class="btn-primary" id="regBtn" onclick="registerStand()">
        ✅ Meld meg på${lotteryOn ? ' og delta i lotteri' : ''}
      </button>
      ${regs.length > 0 ? `<div style="text-align:center;margin-top:1rem;font-size:.85rem;color:#555">${regs.length} påmeldte</div>` : ''}
      <div class="gdpr-note">🔒 Vi lagrer kun navn og e-post for å sende informasjon. Data deles ikke med tredjepart og slettes automatisk etter arrangementet.${contactEmail ? ` <a href="mailto:${escHtml(contactEmail)}" style="color:#888">Kontakt oss</a> for innsyn.` : ''}</div>
    </div>
  </div>

  ${lotteryOn ? `
  <!-- Lotteri -->
  <div class="ev-panel" id="tab-lottery">
    <div class="lottery-box">
      <div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.8px;color:var(--y);font-weight:700;margin-bottom:.25rem">🎰 Lodtrekning</div>
      ${lottery.prize ? `<div style="font-size:.92rem;color:#bbb;margin-bottom:.75rem">Premie: <strong style="color:var(--y)">${escHtml(lottery.prize)}</strong></div>` : ''}
      <span class="lottery-drum" id="lDrum">🎱</span>
      <div id="lWinner"></div>
      <div id="lEligible" style="font-size:.85rem;color:#666;margin-top:.75rem"></div>
    </div>
    <div id="pastWrap" style="margin-top:1rem;display:none">
      <div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.5px;color:#555;margin-bottom:.5rem">Tidligere vinnere</div>
      <div id="pastList"></div>
    </div>
  </div>` : ''}

  <!-- Gjestebok -->
  <div class="ev-panel" id="tab-gb">
    <div id="gbEntries">${gbHtml}</div>
    <div class="ev-card" style="margin-top:1rem">
      <div class="ev-card-title">✍️ Legg igjen en kommentar</div>
      <div id="gbMsg"></div>
      <div class="ev-form">
        <label>Navn *</label>
        <input id="gbName" type="text" placeholder="Ditt navn"/>
        <label>Melding *</label>
        <textarea id="gbMsg2" placeholder="Skriv din kommentar…"></textarea>
      </div>
      <button class="btn-primary" onclick="submitGb()">Send kommentar</button>
      <p style="font-size:.75rem;color:#555;margin-top:.75rem">Kommentarer godkjennes før de vises.</p>
    </div>
  </div>

</div>

<div class="staff-fab"><button class="staff-fab-btn" id="staffFab" onclick="openPinSheet()">👔 Personal</button><span class="staff-fab-hint">Personalinngang</span></div>
${tabletPinSheet(ev)}
${tabletSharedJS(ev)}
<script>
async function registerStand(){
  var btn=document.getElementById('regBtn');
  var msg=document.getElementById('regMsg');
  var name=document.getElementById('rName').value.trim();
  var email=document.getElementById('rEmail').value.trim();
  var phone=document.getElementById('rPhone').value.trim();
  if(!name||!email){msg.innerHTML='<div class="msg msg-err">Navn og e-post er påkrevd</div>';return;}
  btn.disabled=true;btn.textContent='Sender…';
  var r=await fetch('/api/events/'+EV_ID+'/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,email,phone})});
  var d=await r.json();
  btn.disabled=false;btn.textContent='✅ Meld meg på${lotteryOn ? ' og delta i lotteri' : ''}';
  if(r.ok){
    msg.innerHTML='<div class="msg msg-ok">🎉 Takk, '+esc(name)+'! Du er nå påmeldt.</div>';
    document.getElementById('rName').value='';
    document.getElementById('rEmail').value='';
    document.getElementById('rPhone').value='';
  } else {
    msg.innerHTML='<div class="msg msg-err">'+esc(d.error||'Feil')+'</div>';
  }
}

async function submitGb(){
  var name=document.getElementById('gbName').value.trim();
  var msg2=document.getElementById('gbMsg2').value.trim();
  var msg=document.getElementById('gbMsg');
  if(!name||!msg2){msg.innerHTML='<div class="msg msg-err">Navn og melding er påkrevd</div>';return;}
  var r=await fetch('/api/events/'+EV_ID+'/guestbook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,message:msg2})});
  var d=await r.json();
  if(r.ok){
    msg.innerHTML='<div class="msg msg-ok">✅ Takk! Kommentaren din godkjennes av administrator.</div>';
    document.getElementById('gbName').value='';
    document.getElementById('gbMsg2').value='';
  } else {
    msg.innerHTML='<div class="msg msg-err">'+esc(d.err||d.error||'Feil')+'</div>';
  }
}

${lotteryOn ? `
async function loadLottery(){
  var r=await fetch('/api/events/'+EV_ID+'/lottery/winners');
  if(!r.ok)return;
  var d=await r.json();
  var winners=d.winners||[];
  var el=document.getElementById('lEligible');
  if(el)el.textContent=(${regs.length}-winners.length)+' med i trekningen';
  var wrap=document.getElementById('pastWrap');
  var list=document.getElementById('pastList');
  if(winners.length&&wrap&&list){
    wrap.style.display='';
    list.innerHTML=winners.slice().reverse().map(function(w){
      return '<div class="past-winner"><span>🏆 '+esc(w.name)+'</span><span style="color:#555;font-size:.78rem">'+new Date(w.drawnAt).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})+'</span></div>';
    }).join('');
  }
  if(winners.length){
    var last=winners[winners.length-1];
    var wDiv=document.getElementById('lWinner');
    if(wDiv&&wDiv.dataset.shown!==last.regId){
      wDiv.dataset.shown=last.regId;
      wDiv.innerHTML='<div class="winner-pop"><div class="winner-name">🎉 '+esc(last.name)+'!</div>'+(last.prize?'<div style="color:#aaa;font-size:.88rem;margin-top:.25rem">Premie: '+esc(last.prize)+'</div>':'')+'</div>';
    }
  }
}
(function(){
  var es=new EventSource('/api/events/stream?department=${escHtml(ev.department||'')}');
  es.onmessage=function(e){try{var m=JSON.parse(e.data);if(m.type==='events_updated')loadLottery();}catch(ex){}};
  es.onerror=function(){es.close();setTimeout(function(){location.reload();},5000)};
})();
loadLottery();
` : ''}
<\/script>
</body>
</html>`;
}

// ── Møte page ─────────────────────────────────────────────────────
function buildMotePage(ev, isAuthenticated) {
  const settings     = getSettings();
  const regs         = ev.registrations || [];
  const spotsLeft    = ev.maxParticipants ? ev.maxParticipants - regs.filter(r=>!r.anonymized).length : null;
  const isFull       = spotsLeft !== null && spotsLeft <= 0;
  const contactEmail = settings.contactEmail || '';
  const siteName     = escHtml(settings.siteName || 'Events Admin');
  const accentColor  = (settings.colors && settings.colors.accent) || '#FFD100';

  return `<!DOCTYPE html>
<html lang="no">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escHtml(ev.title)} – ${siteName}</title>
${tabletCSS(accentColor)}
</head>
<body>
${tabletHeader(ev, settings, 'badge-mote', '🟡 ' + getTypeLabel('mote', settings))}
${tabletHero(ev, 'badge-mote', '🟡 ' + getTypeLabel('mote', settings))}

<nav class="ev-tabs">
  <div class="ev-tab active" data-tab="info" onclick="showTab('info')">ℹ️ Om møtet</div>
  <div class="ev-tab" data-tab="reg" onclick="showTab('reg')">📋 Meld deg på</div>
  <div class="ev-tab" data-tab="oppmote" onclick="showTab('oppmote')">✅ Oppmøte</div>
</nav>

<div class="ev-content">

  <!-- Info -->
  <div class="ev-panel active" id="tab-info">
    ${ev.description ? `<div class="ev-card"><div class="ev-card-title">Om møtet</div><p style="line-height:1.7;color:#ddd">${escHtml(ev.description).replace(/\n/g,'<br>')}</p></div>` : ''}
    <div class="ev-card">
      <div class="ev-card-title">Praktisk info</div>
      ${ev.date ? `<div class="info-row"><span class="icon">📅</span><div><div class="label">Dato og tid</div><div class="value">${evFmtDate(ev.date)}${ev.date ? ' kl. ' + evFmtTime(ev.date) : ''}</div></div></div>` : ''}
      ${ev.location ? `<div class="info-row"><span class="icon">📍</span><div><div class="label">Sted</div><div class="value">${escHtml(ev.location)}</div></div></div>` : ''}
      ${ev.maxParticipants ? `<div class="info-row"><span class="icon">👥</span><div><div class="label">Plasser</div><div class="value ${isFull?'spots-full':spotsLeft&&spotsLeft<=5?'spots-low':'spots-ok'}">${isFull?'Fullt':''+spotsLeft+' ledige plasser av '+ev.maxParticipants}</div></div></div>` : ''}
      ${contactEmail ? `<div class="info-row"><span class="icon">✉️</span><div><div class="label">Kontakt</div><div class="value"><a href="mailto:${escHtml(contactEmail)}" style="color:var(--y)">${escHtml(contactEmail)}</a></div></div></div>` : ''}
    </div>
    ${!isFull ? `<button class="btn-primary" onclick="showTab('reg')">📋 Meld meg på →</button>` : `<div class="msg msg-err" style="text-align:center;margin-top:.5rem">Dette møtet er fullt</div>`}
  </div>

  <!-- Påmelding -->
  <div class="ev-panel" id="tab-reg">
    <div class="ev-card">
      <div class="ev-card-title">📋 Påmelding</div>
      ${isFull ? `<div class="msg msg-err">Møtet er fullt – ingen ledige plasser.</div>` : `
      <div id="regMsg"></div>
      <div class="ev-form">
        <label>Navn *</label>
        <input id="rName" type="text" placeholder="Ditt fulle navn" autocomplete="name"/>
        <label>E-post *</label>
        <input id="rEmail" type="email" placeholder="din@epost.no" autocomplete="email"/>
        <label>Telefon <span style="color:#666;font-weight:400">(valgfritt)</span></label>
        <input id="rPhone" type="tel" placeholder="+47 000 00 000" autocomplete="tel"/>
        <label>Fremmøteform</label>
        <select id="rAttendance"><option value="">– Velg –</option><option>Fysisk</option><option>Digitalt</option><option>Vet ikke ennå</option></select>
      </div>
      <button class="btn-primary" id="regBtn" onclick="doRegister()">✅ Meld meg på</button>
      `}
      <div class="gdpr-note">🔒 Personopplysninger brukes kun til å administrere møtet og slettes automatisk etterpå.</div>
    </div>
  </div>

  <!-- Oppmøte (kun for innlogget/personal) -->
  <div class="ev-panel" id="tab-oppmote">
    <div class="ev-card">
      <div class="ev-card-title">✅ Oppmøteliste</div>
      <div class="search-wrap ev-form" style="margin-bottom:1rem">
        <span class="search-icon">🔍</span>
        <input type="search" id="regSearch" placeholder="Søk etter navn…" oninput="filterRegs(this.value)" style="padding-left:2.5rem"/>
      </div>
      <div id="regList" class="reg-list">
        ${regs.filter(r=>!r.anonymized).map(function(r){
          return `<div class="reg-item" id="ri-${escHtml(r.id)}" data-name="${escHtml((r.name||'').toLowerCase())}">
            <div>
              <div class="reg-name">${escHtml(r.name)}</div>
              ${r.phone ? `<div class="reg-meta">${escHtml(r.phone)}</div>` : ''}
            </div>
            ${r.checkedIn
              ? `<span class="checkin-done">✔ ${new Date(r.checkedInAt||Date.now()).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})}</span>`
              : `<button class="checkin-btn" onclick="checkInReg('${escHtml(r.id)}')">Sjekk inn</button>`}
          </div>`;
        }).join('') || '<div class="empty"><span class="empty-icon">📋</span>Ingen påmeldte ennå</div>'}
      </div>
      <div style="text-align:center;color:#555;font-size:.85rem;margin-top:.75rem">${regs.filter(r=>!r.anonymized).length} påmeldte · ${regs.filter(r=>r.checkedIn&&!r.anonymized).length} sjekket inn</div>
    </div>
  </div>

</div>

<div class="staff-fab"><button class="staff-fab-btn" id="staffFab" onclick="openPinSheet()">👔 Personal</button><span class="staff-fab-hint">Personalinngang</span></div>
${tabletPinSheet(ev)}
${tabletSharedJS(ev)}
<script>
async function refreshRegList(){
  var r=await fetch('/api/events/'+EV_ID+'/registrations');
  if(!r.ok)return;
  var regs=await r.json();
  var active=regs.filter(function(x){return !x.anonymized;});
  var list=document.getElementById('regList');
  var counter=document.getElementById('regCounter');
  if(!list)return;
  if(!active.length){
    list.innerHTML='<div class="empty"><span class="empty-icon">📋</span>Ingen påmeldte ennå</div>';
  } else {
    list.innerHTML=active.map(function(reg){
      return '<div class="reg-item" id="ri-'+reg.id+'" data-name="'+(reg.name||'').toLowerCase()+'">'
        +'<div><div class="reg-name">'+esc(reg.name)+'</div>'
        +(reg.phone?'<div class="reg-meta">'+esc(reg.phone)+'</div>':'')
        +'</div>'
        +(reg.checkedIn
          ?'<span class="checkin-done">✔ '+new Date(reg.checkedInAt||Date.now()).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})+'</span>'
          :'<button class="checkin-btn" onclick="checkInReg(\''+reg.id+'\')">Sjekk inn</button>')
        +'</div>';
    }).join('');
  }
  if(counter)counter.textContent=active.length+' påmeldte · '+active.filter(function(x){return x.checkedIn;}).length+' sjekket inn';
}
async function doRegister(){
  var btn=document.getElementById('regBtn');
  var msg=document.getElementById('regMsg');
  var name=document.getElementById('rName').value.trim();
  var email=document.getElementById('rEmail').value.trim();
  var phone=document.getElementById('rPhone')?.value.trim()||'';
  var attendance=document.getElementById('rAttendance')?.value||'';
  if(!name||!email){msg.innerHTML='<div class="msg msg-err">Navn og e-post er påkrevd</div>';return;}
  btn.disabled=true;btn.textContent='Sender…';
  var r=await fetch('/api/events/'+EV_ID+'/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,email,phone,attendance})});
  var d=await r.json();
  btn.disabled=false;btn.textContent='✅ Meld meg på';
  if(r.ok){
    msg.innerHTML='<div class="msg msg-ok">🎉 Takk, '+esc(name)+'! Du er påmeldt.</div>';
    document.getElementById('rName').value='';
    document.getElementById('rEmail').value='';
    document.getElementById('rPhone').value='';
    refreshRegList();
  } else {
    msg.innerHTML='<div class="msg msg-err">'+esc(d.error||'Feil')+'</div>';
  }
}

async function checkInReg(id){
  var btn=document.querySelector('#ri-'+id+' .checkin-btn');
  if(btn){btn.disabled=true;btn.textContent='...';}
  var r=await fetch('/api/events/'+EV_ID+'/registrations/'+id+'/checkin',{method:'POST',headers:{'Content-Type':'application/json'}});
  if(r.ok){
    var t=new Date().toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'});
    var item=document.getElementById('ri-'+id);
    if(item){var old=item.querySelector('.checkin-btn');if(old){var sp=document.createElement('span');sp.className='checkin-done';sp.textContent='✔ '+t;old.replaceWith(sp);}}
  }
}

function filterRegs(q){
  q=q.toLowerCase();
  document.querySelectorAll('#regList .reg-item').forEach(function(el){
    el.style.display=(!q||el.dataset.name.includes(q))?'flex':'none';
  });
}
<\/script>
</body>
</html>`;
}

// ── Kurs page ─────────────────────────────────────────────────────
function buildKursPage(ev, isAuthenticated) {
  const settings     = getSettings();
  const regs         = ev.registrations || [];
  const activeRegs   = regs.filter(function(r){ return !r.anonymized; });
  const spotsLeft    = ev.maxParticipants ? ev.maxParticipants - activeRegs.length : null;
  const isFull       = spotsLeft !== null && spotsLeft <= 0;
  const contactEmail = settings.contactEmail || '';
  const siteName     = escHtml(settings.siteName || 'Events Admin');
  const accentColor  = (settings.colors && settings.colors.accent) || '#FFD100';

  const regListHtml = activeRegs.map(function(r){
    return `<div class="reg-item" id="ri-${escHtml(r.id)}" data-name="${escHtml((r.name||'').toLowerCase())}">
      <div>
        <div class="reg-name">${escHtml(r.name)}</div>
        ${r.phone ? `<div class="reg-meta">${escHtml(r.phone)}</div>` : ''}
      </div>
      ${r.checkedIn
        ? `<span class="checkin-done">✔ ${new Date(r.checkedInAt||Date.now()).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})}</span>`
        : `<button class="checkin-btn" onclick="checkInReg('${escHtml(r.id)}')">Sjekk inn</button>`}
    </div>`;
  }).join('') || '<div class="empty"><span class="empty-icon">📋</span>Ingen påmeldte ennå</div>';

  return `<!DOCTYPE html>
<html lang="no">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escHtml(ev.title)} – ${siteName}</title>
${tabletCSS(accentColor)}
</head>
<body>
${tabletHeader(ev, settings, 'badge-kurs', '🔵 ' + getTypeLabel('kurs', settings))}
${tabletHero(ev, 'badge-kurs', '🔵 ' + getTypeLabel('kurs', settings))}

<nav class="ev-tabs">
  <div class="ev-tab active" data-tab="info" onclick="showTab('info')">ℹ️ Om kurset</div>
  <div class="ev-tab" data-tab="reg" onclick="showTab('reg')">📋 Påmelding</div>
  <div class="ev-tab" data-tab="oppmote" onclick="showTab('oppmote')">✅ Oppmøte</div>
  <div class="ev-tab" data-tab="gb" onclick="showTab('gb')">✍️ Gjestebok</div>
</nav>

<div class="ev-content">

  <!-- Info -->
  <div class="ev-panel active" id="tab-info">
    ${ev.description ? `<div class="ev-card"><div class="ev-card-title">Om kurset</div><p style="line-height:1.7;color:#ddd">${escHtml(ev.description).replace(/\n/g,'<br>')}</p></div>` : ''}
    <div class="ev-card">
      <div class="ev-card-title">Praktisk info</div>
      ${ev.date ? `<div class="info-row"><span class="icon">📅</span><div><div class="label">Dato og tid</div><div class="value">${evFmtDate(ev.date)}${ev.date ? ' kl. ' + evFmtTime(ev.date) : ''}</div></div></div>` : ''}
      ${ev.location ? `<div class="info-row"><span class="icon">📍</span><div><div class="label">Sted</div><div class="value">${escHtml(ev.location)}</div></div></div>` : ''}
      ${ev.maxParticipants ? `<div class="info-row"><span class="icon">👥</span><div><div class="label">Ledige plasser</div><div class="value ${isFull?'spots-full':spotsLeft&&spotsLeft<=3?'spots-low':'spots-ok'}">${isFull ? 'Kurset er fullt' : spotsLeft + ' av ' + ev.maxParticipants + ' ledige'}</div></div></div>` : ''}
      ${contactEmail ? `<div class="info-row"><span class="icon">✉️</span><div><div class="label">Kontakt</div><div class="value"><a href="mailto:${escHtml(contactEmail)}" style="color:var(--y)">${escHtml(contactEmail)}</a></div></div></div>` : ''}
    </div>
    ${!isFull
      ? `<button class="btn-primary" onclick="showTab('reg')">📋 Meld deg på kurset →</button>`
      : `<div class="msg msg-err" style="text-align:center;margin-top:.5rem">Kurset er fullt</div>`}
  </div>

  <!-- Påmelding -->
  <div class="ev-panel" id="tab-reg">
    <div class="ev-card">
      <div class="ev-card-title">📋 Påmelding</div>
      ${isFull ? `<div class="msg msg-err">Kurset er fullt – ingen ledige plasser.</div>` : `
      <div id="regMsg"></div>
      <div class="ev-form">
        <label>Navn *</label>
        <input id="rName" type="text" placeholder="Ditt fulle navn" autocomplete="name"/>
        <label>E-post *</label>
        <input id="rEmail" type="email" placeholder="din@epost.no" autocomplete="email"/>
        <label>Telefon <span style="color:#666;font-weight:400">(valgfritt)</span></label>
        <input id="rPhone" type="tel" placeholder="+47 000 00 000" autocomplete="tel"/>
      </div>
      <button class="btn-primary" id="regBtn" onclick="doRegister()">✅ Meld meg på kurset</button>
      `}
      <div class="gdpr-note">🔒 Personopplysninger brukes kun til å administrere kurset og slettes automatisk etterpå.</div>
    </div>
  </div>

  <!-- Oppmøte -->
  <div class="ev-panel" id="tab-oppmote">
    <div class="ev-card">
      <div class="ev-card-title">✅ Oppmøteliste</div>
      <div class="search-wrap ev-form" style="margin-bottom:1rem">
        <span class="search-icon">🔍</span>
        <input type="search" id="regSearch" placeholder="Søk etter navn…" oninput="filterRegs(this.value)" style="padding-left:2.5rem"/>
      </div>
      <div id="regList" class="reg-list">${regListHtml}</div>
      <div style="text-align:center;color:#555;font-size:.85rem;margin-top:.75rem">
        ${activeRegs.length} påmeldte · ${activeRegs.filter(r=>r.checkedIn).length} sjekket inn
      </div>
    </div>
  </div>

  <!-- Gjestebok -->
  <div class="ev-panel" id="tab-gb">
    <div id="gbEntries">
      ${(ev.guestbook||[]).filter(g=>g.approved).length
        ? (ev.guestbook||[]).filter(g=>g.approved).map(function(g){
            return `<div class="gb-entry"><div class="gb-name">${escHtml(g.name)}</div><div class="gb-msg">${escHtml(g.message).replace(/\n/g,'<br>')}</div><div class="gb-date">${new Date(g.createdAt).toLocaleDateString('nb-NO',{day:'numeric',month:'long',year:'numeric'})}</div></div>`;
          }).join('')
        : '<div class="empty"><span class="empty-icon">✍️</span>Ingen kommentarer ennå</div>'}
    </div>
    <div class="ev-card" style="margin-top:1rem">
      <div class="ev-card-title">✍️ Legg igjen en kommentar</div>
      <div id="gbMsg"></div>
      <div class="ev-form">
        <label>Navn *</label><input id="gbName" type="text" placeholder="Ditt navn"/>
        <label>Melding *</label><textarea id="gbMsg2" placeholder="Skriv din kommentar…"></textarea>
      </div>
      <button class="btn-primary" onclick="submitGb()">Send kommentar</button>
      <p style="font-size:.75rem;color:#555;margin-top:.75rem">Kommentarer godkjennes før de vises.</p>
    </div>
  </div>

</div>

<div class="staff-fab"><button class="staff-fab-btn" id="staffFab" onclick="openPinSheet()">👔 Personal</button><span class="staff-fab-hint">Personalinngang</span></div>
${tabletPinSheet(ev)}
${tabletSharedJS(ev)}
<script>
async function refreshRegList(){
  var r=await fetch('/api/events/'+EV_ID+'/registrations');
  if(!r.ok)return;
  var regs=await r.json();
  var active=regs.filter(function(x){return !x.anonymized;});
  var list=document.getElementById('regList');
  var counter=document.getElementById('regCounter');
  if(!list)return;
  if(!active.length){
    list.innerHTML='<div class="empty"><span class="empty-icon">📋</span>Ingen påmeldte ennå</div>';
  } else {
    list.innerHTML=active.map(function(reg){
      return '<div class="reg-item" id="ri-'+reg.id+'" data-name="'+(reg.name||'').toLowerCase()+'">'
        +'<div><div class="reg-name">'+esc(reg.name)+'</div>'
        +(reg.phone?'<div class="reg-meta">'+esc(reg.phone)+'</div>':'')
        +'</div>'
        +(reg.checkedIn
          ?'<span class="checkin-done">✔ '+new Date(reg.checkedInAt||Date.now()).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})+'</span>'
          :'<button class="checkin-btn" onclick="checkInReg(\''+reg.id+'\')">Sjekk inn</button>')
        +'</div>';
    }).join('');
  }
  if(counter)counter.textContent=active.length+' påmeldte · '+active.filter(function(x){return x.checkedIn;}).length+' sjekket inn';
}
async function doRegister(){
  var btn=document.getElementById('regBtn');
  var msg=document.getElementById('regMsg');
  var name=document.getElementById('rName').value.trim();
  var email=document.getElementById('rEmail').value.trim();
  var phone=document.getElementById('rPhone')?.value.trim()||'';
  if(!name||!email){msg.innerHTML='<div class="msg msg-err">Navn og e-post er påkrevd</div>';return;}
  btn.disabled=true;btn.textContent='Sender…';
  var r=await fetch('/api/events/'+EV_ID+'/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,email,phone})});
  var d=await r.json();
  btn.disabled=false;btn.textContent='✅ Meld meg på kurset';
  if(r.ok){
    msg.innerHTML='<div class="msg msg-ok">🎉 Takk, '+esc(name)+'! Du er påmeldt kurset.</div>';
    document.getElementById('rName').value='';
    document.getElementById('rEmail').value='';
    document.getElementById('rPhone').value='';
    refreshRegList();
  } else {
    msg.innerHTML='<div class="msg msg-err">'+esc(d.error||'Feil')+'</div>';
  }
}

async function checkInReg(id){
  var btn=document.querySelector('#ri-'+id+' .checkin-btn');
  if(btn){btn.disabled=true;btn.textContent='...';}
  var r=await fetch('/api/events/'+EV_ID+'/registrations/'+id+'/checkin',{method:'POST',headers:{'Content-Type':'application/json'}});
  if(r.ok){
    var t=new Date().toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'});
    var item=document.getElementById('ri-'+id);
    if(item){var old=item.querySelector('.checkin-btn');if(old){var sp=document.createElement('span');sp.className='checkin-done';sp.textContent='✔ '+t;old.replaceWith(sp);}}
  }
}

function filterRegs(q){
  q=q.toLowerCase();
  document.querySelectorAll('#regList .reg-item').forEach(function(el){
    el.style.display=(!q||el.dataset.name.includes(q))?'flex':'none';
  });
}

async function submitGb(){
  var name=document.getElementById('gbName').value.trim();
  var msg2=document.getElementById('gbMsg2').value.trim();
  var msg=document.getElementById('gbMsg');
  if(!name||!msg2){msg.innerHTML='<div class="msg msg-err">Navn og melding er påkrevd</div>';return;}
  var r=await fetch('/api/events/'+EV_ID+'/guestbook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,message:msg2})});
  if(r.ok){msg.innerHTML='<div class="msg msg-ok">✅ Takk! Godkjennes av administrator.</div>';document.getElementById('gbName').value='';document.getElementById('gbMsg2').value='';}
  else{var d=await r.json();msg.innerHTML='<div class="msg msg-err">'+esc(d.err||d.error||'Feil')+'</div>';}
}
<\/script>
</body>
</html>`;
}

// ── Tur page ──────────────────────────────────────────────────────
function buildTurPage(ev, isAuthenticated) {
  const settings     = getSettings();
  const regs         = ev.registrations || [];
  const activeRegs   = regs.filter(function(r){ return !r.anonymized; });
  const spotsLeft    = ev.maxParticipants ? ev.maxParticipants - activeRegs.length : null;
  const isFull       = spotsLeft !== null && spotsLeft <= 0;
  const contactEmail = settings.contactEmail || '';
  const siteName     = escHtml(settings.siteName || 'Events Admin');
  const accentColor  = (settings.colors && settings.colors.accent) || '#FFD100';
  const route        = ev.route || {};
  const days         = route.days || [];
  const isMultiday   = !!(ev.endDate && ev.endDate > (ev.date || '').slice(0,10));

  const etappeHtml = days.length
    ? days.map(function(day, di){
        const stops = (day.stops || []).filter(function(s){ return s.name; });
        if (!stops.length) return '';
        return `<div style="margin-bottom:1.25rem">
          <div style="font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.5px;color:var(--y);margin-bottom:.5rem">Dag ${di+1}${day.label ? ' – '+escHtml(day.label) : ''}</div>
          ${stops.map(function(s,si){
            return `<div class="etappe-item">
              <div class="etappe-num">Stopp ${si+1}</div>
              <div class="etappe-name">${escHtml(s.name)}</div>
              <div class="etappe-meta">
                ${s.distanceFromPrev ? `<span>📏 ${s.distanceFromPrev} km</span>` : ''}
                ${s.fuelStop ? `<span>⛽ Bensinstopp</span>` : ''}
                ${s.type ? `<span>${escHtml(s.type)}</span>` : ''}
              </div>
            </div>`;
          }).join('')}
        </div>`;
      }).join('')
    : '<div class="empty"><span class="empty-icon">🗺️</span>Ingen etappeplan lagt inn ennå</div>';

  const regListHtml = activeRegs.map(function(r){
    const v = r.vehicle || {};
    return `<div class="reg-item" id="ri-${escHtml(r.id)}" data-name="${escHtml((r.name||'').toLowerCase())}">
      <div>
        <div class="reg-name">${escHtml(r.name)}</div>
        ${v.make ? `<div class="reg-meta">🏍 ${escHtml(v.make)} ${escHtml(v.model||'')} ${v.reg ? '· '+escHtml(v.reg) : ''}</div>` : ''}
      </div>
      ${r.checkedIn
        ? `<span class="checkin-done">✔ ${new Date(r.checkedInAt||Date.now()).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})}</span>`
        : `<button class="checkin-btn" onclick="checkInReg('${escHtml(r.id)}')">Sjekk inn</button>`}
    </div>`;
  }).join('') || '<div class="empty"><span class="empty-icon">🏍</span>Ingen påmeldte ennå</div>';

  return `<!DOCTYPE html>
<html lang="no">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escHtml(ev.title)} – ${siteName}</title>
${tabletCSS(accentColor)}
</head>
<body>
${tabletHeader(ev, settings, 'badge-tur', '🟣 ' + getTypeLabel('tur', settings))}
${tabletHero(ev, 'badge-tur', '🟣 ' + getTypeLabel('tur', settings))}

<nav class="ev-tabs">
  <div class="ev-tab active" data-tab="info" onclick="showTab('info')">ℹ️ Om turen</div>
  <div class="ev-tab" data-tab="rute" onclick="showTab('rute')">🗺️ Etappeplan</div>
  <div class="ev-tab" data-tab="reg" onclick="showTab('reg')">📋 Påmelding</div>
  <div class="ev-tab" data-tab="forere" onclick="showTab('forere')">🏍 Deltagere</div>
  <div class="ev-tab" data-tab="gb" onclick="showTab('gb')">✍️ Gjestebok</div>
</nav>

<div class="ev-content">

  <!-- Info -->
  <div class="ev-panel active" id="tab-info">
    ${ev.description ? `<div class="ev-card"><div class="ev-card-title">Om turen</div><p style="line-height:1.7;color:#ddd">${escHtml(ev.description).replace(/\n/g,'<br>')}</p></div>` : ''}
    <div class="ev-card">
      <div class="ev-card-title">Praktisk info</div>
      ${ev.date ? `<div class="info-row"><span class="icon">📅</span><div><div class="label">Avreise</div><div class="value">${evFmtDate(ev.date)} kl. ${evFmtTime(ev.date)}</div></div></div>` : ''}
      ${ev.location ? `<div class="info-row"><span class="icon">📍</span><div><div class="label">Oppmøtested</div><div class="value">${escHtml(ev.location)}</div></div></div>` : ''}
      ${days.length ? `<div class="info-row"><span class="icon">🗓</span><div><div class="label">Antall dager</div><div class="value">${days.length} dag${days.length>1?'er':''}</div></div></div>` : ''}
      ${ev.maxParticipants ? `<div class="info-row"><span class="icon">🏍</span><div><div class="label">Ledige plasser</div><div class="value ${isFull?'spots-full':spotsLeft&&spotsLeft<=3?'spots-low':'spots-ok'}">${isFull ? 'Turen er full' : spotsLeft + ' av ' + ev.maxParticipants + ' ledige'}</div></div></div>` : ''}
      ${contactEmail ? `<div class="info-row"><span class="icon">✉️</span><div><div class="label">Kontakt</div><div class="value"><a href="mailto:${escHtml(contactEmail)}" style="color:var(--y)">${escHtml(contactEmail)}</a></div></div></div>` : ''}
    </div>
    ${!isFull
      ? `<button class="btn-primary" onclick="showTab('reg')">📋 Meld deg på turen →</button>`
      : `<div class="msg msg-err" style="text-align:center;margin-top:.5rem">Turen er full</div>`}
  </div>

  <!-- Etappeplan -->
  <div class="ev-panel" id="tab-rute">
    <div class="ev-card">
      <div class="ev-card-title">🗺️ Etappeplan</div>
      ${etappeHtml}
    </div>
  </div>

  <!-- Påmelding -->
  <div class="ev-panel" id="tab-reg">
    <div class="ev-card">
      <div class="ev-card-title">📋 Påmelding</div>
      ${ev.isFinalized ? `<div class="msg" style="background:#0a2a0a;border:1px solid #166534;color:#4ade80;border-radius:6px;padding:.75rem 1rem;margin-bottom:.75rem;font-size:.9rem">✅ Turen er ferdigplanlagt! Du vil få en detaljert reisebeskrivelse på e-post.</div>` : ''}
      ${isFull ? `<div class="msg msg-err">Turen er full – ingen ledige plasser.</div>` : `
      <div id="regMsg"></div>
      <div class="ev-form">
        <label>Navn *</label>
        <input id="rName" type="text" placeholder="Ditt fulle navn" autocomplete="name"/>
        <label>E-post *</label>
        <input id="rEmail" type="email" placeholder="din@epost.no" autocomplete="email"/>
        <label>Telefon</label>
        <input id="rPhone" type="tel" placeholder="+47 000 00 000" autocomplete="tel"/>
        <label>MC-merke</label>
        <input id="rMake" type="text" placeholder="Honda, Yamaha, BMW…"/>
        <label>MC-modell</label>
        <input id="rModel" type="text" placeholder="Modell"/>
        <label>Nødkontakt – navn</label>
        <input id="rEcName" type="text" placeholder="Navn på nødkontakt"/>
        <label>Nødkontakt – telefon</label>
        <input id="rEcPhone" type="tel" placeholder="+47 000 00 000"/>
        ${isMultiday ? `
        <label>Hotellrom</label>
        <select id="rHotelRoom">
          <option value="">– Velg romtype –</option>
          <option value="enkel">🛏 Enkeltrom</option>
          <option value="dobbelt">🛏🛏 Dobbeltrom</option>
        </select>` : ''}
      </div>
      <button class="btn-primary" id="regBtn" onclick="doRegister()">✅ Meld meg på turen</button>
      `}
      <div class="gdpr-note">🔒 Personopplysninger brukes kun til å administrere turen og slettes automatisk etterpå.</div>
    </div>
  </div>

  <!-- Deltagere -->
  <div class="ev-panel" id="tab-forere">
    <div class="ev-card">
      <div class="ev-card-title">🏍 Deltagere</div>
      <div class="search-wrap ev-form" style="margin-bottom:1rem">
        <span class="search-icon">🔍</span>
        <input type="search" id="regSearch" placeholder="Søk etter navn…" oninput="filterRegs(this.value)" style="padding-left:2.5rem"/>
      </div>
      <div id="regList" class="reg-list">${regListHtml}</div>
      <div style="text-align:center;color:#555;font-size:.85rem;margin-top:.75rem">
        ${activeRegs.length} påmeldte · ${activeRegs.filter(r=>r.checkedIn).length} sjekket inn
      </div>
    </div>
  </div>

  <!-- Gjestebok -->
  <div class="ev-panel" id="tab-gb">
    <div id="gbEntries">
      ${(ev.guestbook||[]).filter(g=>g.approved).length
        ? (ev.guestbook||[]).filter(g=>g.approved).map(function(g){
            return `<div class="gb-entry"><div class="gb-name">${escHtml(g.name)}</div><div class="gb-msg">${escHtml(g.message).replace(/\n/g,'<br>')}</div><div class="gb-date">${new Date(g.createdAt).toLocaleDateString('nb-NO',{day:'numeric',month:'long',year:'numeric'})}</div></div>`;
          }).join('')
        : '<div class="empty"><span class="empty-icon">✍️</span>Ingen kommentarer ennå</div>'}
    </div>
    <div class="ev-card" style="margin-top:1rem">
      <div class="ev-card-title">✍️ Legg igjen en kommentar</div>
      <div id="gbMsg"></div>
      <div class="ev-form">
        <label>Navn *</label><input id="gbName" type="text" placeholder="Ditt navn"/>
        <label>Melding *</label><textarea id="gbMsg2" placeholder="Skriv din kommentar…"></textarea>
      </div>
      <button class="btn-primary" onclick="submitGb()">Send kommentar</button>
      <p style="font-size:.75rem;color:#555;margin-top:.75rem">Kommentarer godkjennes før de vises.</p>
    </div>
  </div>

</div>

<div class="staff-fab"><button class="staff-fab-btn" id="staffFab" onclick="openPinSheet()">👔 Personal</button><span class="staff-fab-hint">Personalinngang</span></div>
${tabletPinSheet(ev)}
${tabletSharedJS(ev)}
<script>
async function refreshRegList(){
  var r=await fetch('/api/events/'+EV_ID+'/registrations');
  if(!r.ok)return;
  var regs=await r.json();
  var active=regs.filter(function(x){return !x.anonymized;});
  var list=document.getElementById('regList');
  var counter=document.getElementById('regCounter');
  if(!list)return;
  if(!active.length){
    list.innerHTML='<div class="empty"><span class="empty-icon">🏍</span>Ingen påmeldte ennå</div>';
  } else {
    list.innerHTML=active.map(function(reg){
      return '<div class="reg-item" id="ri-'+reg.id+'" data-name="'+( reg.name||'').toLowerCase()+'">'+
        '<div><div class="reg-name">'+esc(reg.name)+'</div>'+
        (reg.phone?'<div class="reg-meta">'+esc(reg.phone)+'</div>':'')+
        '</div>'+
        (reg.checkedIn
          ?'<span class="checkin-done">✔ '+new Date(reg.checkedInAt||Date.now()).toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'})+'</span>'
          :'<button class="checkin-btn" onclick="checkInReg(\''+reg.id+'\')">Sjekk inn</button>')+
        '</div>';
    }).join('');
  }
  if(counter)counter.textContent=active.length+' påmeldte · '+active.filter(function(x){return x.checkedIn;}).length+' sjekket inn';
}

async function doRegister(){
  var btn=document.getElementById('regBtn');
  var msg=document.getElementById('regMsg');
  var name=document.getElementById('rName').value.trim();
  var email=document.getElementById('rEmail').value.trim();
  var phone=document.getElementById('rPhone')?.value.trim()||'';  var make=document.getElementById('rMake')?.value.trim()||'';  var model=document.getElementById('rModel')?.value.trim()||'';  var ecName=document.getElementById('rEcName')?.value.trim()||'';  var ecPhone=document.getElementById('rEcPhone')?.value.trim()||'';  var hotelRoom=document.getElementById('rHotelRoom')?.value||'';  if(!name||!email){msg.innerHTML='<div class="msg msg-err">Navn og e-post er påkrevd</div>';return;}
  btn.disabled=true;btn.textContent='Sender…';
  var body={name,email,phone};
  if(make)body.vehicle={make,model};
  if(ecName)body.emergency={name:ecName,phone:ecPhone};
  if(hotelRoom)body.hotelRoom=hotelRoom;
  var r=await fetch('/api/events/'+EV_ID+'/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  var d=await r.json();
  btn.disabled=false;btn.textContent='✅ Meld meg på turen';
  if(r.ok){
    msg.innerHTML='<div class="msg msg-ok">🎉 Takk, '+esc(name)+'! Du er påmeldt turen.</div>';
    ['rName','rEmail','rPhone','rMake','rModel','rEcName','rEcPhone','rHotelRoom'].forEach(function(id){var el=document.getElementById(id);if(el)el.value='';});
    refreshRegList();
  } else {
    msg.innerHTML='<div class="msg msg-err">'+esc(d.error||'Feil')+'</div>';
  }
}

async function checkInReg(id){
  var btn=document.querySelector('#ri-'+id+' .checkin-btn');
  if(btn){btn.disabled=true;btn.textContent='...';}
  var r=await fetch('/api/events/'+EV_ID+'/registrations/'+id+'/checkin',{method:'POST',headers:{'Content-Type':'application/json'}});
  if(r.ok){
    var t=new Date().toLocaleTimeString('nb-NO',{hour:'2-digit',minute:'2-digit'});
    var item=document.getElementById('ri-'+id);
    if(item){var old=item.querySelector('.checkin-btn');if(old){var sp=document.createElement('span');sp.className='checkin-done';sp.textContent='✔ '+t;old.replaceWith(sp);}}
  }
}

function filterRegs(q){
  q=q.toLowerCase();
  document.querySelectorAll('#regList .reg-item').forEach(function(el){
    el.style.display=(!q||el.dataset.name.includes(q))?'flex':'none';
  });
}

async function submitGb(){
  var name=document.getElementById('gbName').value.trim();
  var msg2=document.getElementById('gbMsg2').value.trim();
  var msg=document.getElementById('gbMsg');
  if(!name||!msg2){msg.innerHTML='<div class="msg msg-err">Navn og melding er påkrevd</div>';return;}
  var r=await fetch('/api/events/'+EV_ID+'/guestbook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,message:msg2})});
  if(r.ok){msg.innerHTML='<div class="msg msg-ok">✅ Takk! Godkjennes av administrator.</div>';document.getElementById('gbName').value='';document.getElementById('gbMsg2').value='';}
  else{var d=await r.json();msg.innerHTML='<div class="msg msg-err">'+esc(d.err||d.error||'Feil')+'</div>';}
}
<\/script>
</body>
</html>`;
}



// ── Offline snapshot (alt siden trenger for å fungere offline) ────
app.get("/api/events/:id/snapshot", function(req, res) {
  const ev = readJSON(EVENTS_FILE).find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  const s = getSettings();
  // Send kun det som trengs – ikke staffPin i klartekst
  res.json({
    id: ev.id, slug: ev.slug, title: ev.title, description: ev.description,
    date: ev.date, location: ev.location, eventType: ev.eventType,
    image: ev.image, maxParticipants: ev.maxParticipants, showParticipants: ev.showParticipants,
    hasPin: !!ev.staffPin,
    registrations: (ev.registrations || []).map(function(r) {
      return { id: r.id, name: r.name, checkedIn: !!r.checkedIn, checkedInAt: r.checkedInAt || null, checkinPin: r.checkinPin || null };
    }),
    staff: (ev.staff || []).map(function(s) {
      return { id: s.id, name: s.name, role: s.role || "", checkedIn: !!s.checkedIn, checkedInAt: s.checkedInAt || null };
    }),
    guestbook: (ev.guestbook || []).filter(function(g) { return g.approved; }).map(function(g) {
      return { id: g.id, name: g.name, message: g.message, createdAt: g.createdAt };
    }),
    snapshotAt: new Date().toISOString(),
  });
});

// ── Offline sync – tar imot kø fra SW og utfører operasjonene ─────
app.post("/api/events/:id/sync", rateLimit(30, 60000), function(req, res) {
  const ops = req.body.ops;
  if (!Array.isArray(ops)) return res.status(400).json({ error: "Ugyldig format" });
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id || e.slug === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });

  var results = [];
  ops.forEach(function(op) {
    try {
      if (op.type === "checkin_reg") {
        var r = (ev.registrations || []).find(function(r) { return r.id === op.regId; });
        if (r && !r.checkedIn) { r.checkedIn = true; r.checkedInAt = op.ts || new Date().toISOString(); }
        results.push({ id: op.id, ok: true });
      } else if (op.type === "checkin_staff") {
        var s = (ev.staff || []).find(function(s) { return s.id === op.staffId; });
        if (s && !s.checkedIn) { s.checkedIn = true; s.checkedInAt = op.ts || new Date().toISOString(); }
        results.push({ id: op.id, ok: true });
      } else if (op.type === "self_checkin_staff") {
        if (!ev.staff) ev.staff = [];
        var name = (op.name || "").trim().slice(0, 100);
        if (name) {
          ev.staff.push({ id: uuid(), name: name, role: (op.role||"").slice(0,100), checkedIn: true, addedAt: op.ts, checkedInAt: op.ts });
        }
        results.push({ id: op.id, ok: true });
      } else if (op.type === "register") {
        if (!ev.registrations) ev.registrations = [];
        var email = (op.email || "").toLowerCase().trim();
        var name  = (op.name  || "").trim().slice(0, 100);
        if (name && email && !ev.registrations.find(function(r){ return r.email === email; })) {
          ev.registrations.push({ id: uuid(), name: name, email: email, phone: (op.phone||"").slice(0,30), registeredAt: op.ts, offlineSync: true });
        }
        results.push({ id: op.id, ok: true });
      } else if (op.type === "guestbook") {
        if (!ev.guestbook) ev.guestbook = [];
        var gbName = (op.name || "").trim().slice(0, 100);
        var gbMsg  = (op.message || "").trim().slice(0, 1000);
        if (gbName && gbMsg) {
          ev.guestbook.push({ id: uuid(), name: gbName, message: gbMsg, approved: false, createdAt: op.ts, offlineSync: true });
        }
        results.push({ id: op.id, ok: true });
      } else {
        results.push({ id: op.id, ok: false, error: "Ukjent operasjon" });
      }
    } catch(e) {
      results.push({ id: op.id, ok: false, error: e.message });
    }
  });
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(null);
  res.json({ ok: true, results: results });
});


// ── Inventar ─────────────────────────────────────────────────────
app.get("/api/inventar", auth, function(req, res) {
  const user  = req.session.user;
  const items = readJSON(INVENTAR_FILE);
  if (user.role === "admin") return res.json(items);
  // Non-admin: return items belonging to their departments + items with no department
  const myDeptIds = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {})
    .map(function(a){ return a.department; }).filter(Boolean);
  res.json(items.filter(function(i){ return !i.department || myDeptIds.includes(i.department); }));
});

app.post("/api/inventar", auth, managerOrAdmin, function(req, res) {
  const user  = req.session.user;
  const items = readJSON(INVENTAR_FILE);
  // Determine department: use provided value if admin, else use caller's department
  let deptId = req.body.department || null;
  if (user.role !== "admin") {
    const myDepts = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {})
      .map(function(a){ return a.department; }).filter(Boolean);
    deptId = myDepts[0] || null;
  }
  const item = {
    id: uuid(), navn: (req.body.navn||"").trim(),
    kategori: req.body.kategori||"annet",
    antall: parseInt(req.body.antall)||0,
    perPakke: parseInt(req.body.perPakke)||1,
    innkjopspris: req.body.innkjopspris != null ? (parseFloat(req.body.innkjopspris)||null) : null,
    beskrivelse: (req.body.beskrivelse||"").trim(),
    bilde: req.body.bilde || null,
    department: deptId,
    usageCount: 0, createdAt: new Date().toISOString()
  };
  if (req.body.pris !== undefined) item.pris = parseFloat(req.body.pris) || 0;
  if (!item.navn) return res.status(400).json({ err: "Navn er påkrevd" });
  items.push(item);
  writeJSON(INVENTAR_FILE, items);
  res.json(item);
});

app.put("/api/inventar/:id", auth, managerOrAdmin, function(req, res) {
  const user  = req.session.user;
  const items = readJSON(INVENTAR_FILE);
  const idx   = items.findIndex(function(i){ return i.id === req.params.id; });
  if (idx === -1) return res.status(404).json({ err: "Ikke funnet" });
  // Check access: admin always OK; manager must own this dept
  const item = items[idx];
  if (user.role !== "admin" && item.department) {
    const myDepts = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {})
      .map(function(a){ return a.department; });
    if (!myDepts.includes(item.department))
      return res.status(403).json({ err: "Ingen tilgang til dette utstyret" });
  }
  items[idx] = Object.assign({}, item, {
    navn:         (req.body.navn||item.navn).trim(),
    kategori:     req.body.kategori    || item.kategori,
    antall:       parseInt(req.body.antall) >= 0 ? parseInt(req.body.antall) : item.antall,
    perPakke:     parseInt(req.body.perPakke)||item.perPakke||1,
    innkjopspris: req.body.innkjopspris != null ? (parseFloat(req.body.innkjopspris)||null) : item.innkjopspris||null,
    beskrivelse:  (req.body.beskrivelse||"").trim(),
    bilde:        req.body.bilde !== undefined ? (req.body.bilde || null) : (item.bilde||null),
    department:   user.role === "admin" && req.body.department !== undefined
                    ? (req.body.department || null)
                    : item.department,
  });
  if (req.body.pris !== undefined) items[idx].pris = parseFloat(req.body.pris) || 0;
  writeJSON(INVENTAR_FILE, items);
  res.json(items[idx]);
});

app.delete("/api/inventar/:id", auth, managerOrAdmin, function(req, res) {
  const user  = req.session.user;
  const items = readJSON(INVENTAR_FILE);
  const item  = items.find(function(i){ return i.id === req.params.id; });
  if (!item) return res.status(404).json({ err: "Ikke funnet" });
  if (user.role !== "admin" && item.department) {
    const myDepts = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {})
      .map(function(a){ return a.department; });
    if (!myDepts.includes(item.department))
      return res.status(403).json({ err: "Ingen tilgang" });
  }
  writeJSON(INVENTAR_FILE, items.filter(function(i){ return i.id !== req.params.id; }));
  // Remove from all events too
  const events = readJSON(EVENTS_FILE);
  events.forEach(e => { if (e.utstyr) e.utstyr = e.utstyr.filter(u => u.id !== req.params.id); });
  writeJSON(EVENTS_FILE, events);
  res.json({ ok: true });
});

// Innkjøp – legg til antall på lager
app.post("/api/inventar/:id/inkjop", auth, managerOrAdmin, function(req, res) {
  const user  = req.session.user;
  const items = readJSON(INVENTAR_FILE);
  const idx   = items.findIndex(function(i){ return i.id === req.params.id; });
  if (idx === -1) return res.status(404).json({ err: "Ikke funnet" });
  if (user.role !== "admin" && items[idx].department) {
    const myDepts = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {})
      .map(function(a){ return a.department; });
    if (!myDepts.includes(items[idx].department))
      return res.status(403).json({ err: "Ingen tilgang" });
  }
  const antall = parseInt(req.body.antall) || 0;
  if (antall <= 0) return res.status(400).json({ err: "Antall må være større enn 0" });
  items[idx].antall = (items[idx].antall || 0) + antall;
  if (!items[idx].inkjopLogg) items[idx].inkjopLogg = [];
  items[idx].inkjopLogg.push({ antall, dato: new Date().toISOString(), notat: (req.body.notat||"").trim() });
  writeJSON(INVENTAR_FILE, items);
  res.json({ ok: true, antall: items[idx].antall });
});

// Varetelling – sett nytt lagersaldo direkte
app.post("/api/inventar/:id/varetelling", auth, managerOrAdmin, function(req, res) {
  const user  = req.session.user;
  const items = readJSON(INVENTAR_FILE);
  const idx   = items.findIndex(function(i){ return i.id === req.params.id; });
  if (idx === -1) return res.status(404).json({ err: "Ikke funnet" });
  if (user.role !== "admin" && items[idx].department) {
    const myDepts = getAccessList(readJSON(USERS_FILE).find(function(u){ return u.id === user.id; }) || {})
      .map(function(a){ return a.department; });
    if (!myDepts.includes(items[idx].department))
      return res.status(403).json({ err: "Ingen tilgang" });
  }
  const nyttAntall = parseInt(req.body.antall);
  if (isNaN(nyttAntall) || nyttAntall < 0) return res.status(400).json({ err: "Ugyldig antall" });
  const gammelt = items[idx].antall || 0;
  items[idx].antall = nyttAntall;
  if (!items[idx].varetellingLogg) items[idx].varetellingLogg = [];
  items[idx].varetellingLogg.push({ fra: gammelt, til: nyttAntall, dato: new Date().toISOString(), notat: (req.body.notat||"").trim() });
  writeJSON(INVENTAR_FILE, items);
  res.json({ ok: true, antall: nyttAntall });
});

// Give-away statistikk per event
app.get("/api/events/:id/giveaway", auth, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ err: "Ikke funnet" });
  res.json(ev.giveaway || []);
});

app.post("/api/events/:id/giveaway", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const evIdx = events.findIndex(e => e.id === req.params.id);
  if (evIdx === -1) return res.status(404).json({ err: "Ikke funnet" });
  if (!events[evIdx].giveaway) events[evIdx].giveaway = [];
  const { itemId, utDelt, retur } = req.body;
  const existing = events[evIdx].giveaway.findIndex(g => g.id === itemId);
  if (existing >= 0) {
    events[evIdx].giveaway[existing].utDelt = parseInt(utDelt) || 0;
    events[evIdx].giveaway[existing].retur  = parseInt(retur)  || 0;
  } else {
    events[evIdx].giveaway.push({ id: itemId, utDelt: parseInt(utDelt)||0, retur: parseInt(retur)||0 });
  }
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

// Salg per event
app.get("/api/events/:id/salg", auth, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ err: "Ikke funnet" });
  res.json(ev.salg || []);
});

app.post("/api/events/:id/salg", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const evIdx = events.findIndex(e => e.id === req.params.id);
  if (evIdx === -1) return res.status(404).json({ err: "Ikke funnet" });
  if (!events[evIdx].salg) events[evIdx].salg = [];
  const { itemId, solgt } = req.body;
  const existing = events[evIdx].salg.findIndex(s => s.id === itemId);
  if (existing >= 0) {
    events[evIdx].salg[existing].solgt = parseInt(solgt) || 0;
  } else {
    events[evIdx].salg.push({ id: itemId, solgt: parseInt(solgt)||0 });
  }
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  res.json({ ok: true });
});

// Utstyr per event
app.get("/api/events/:id/utstyr", auth, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ err: "Ikke funnet" });
  res.json(ev.utstyr || []);
});

app.post("/api/events/:id/utstyr", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const evIdx = events.findIndex(e => e.id === req.params.id);
  if (evIdx === -1) return res.status(404).json({ err: "Ikke funnet" });
  if (!events[evIdx].utstyr) events[evIdx].utstyr = [];
  const { itemId, antall, aktiv } = req.body;
  const existing = events[evIdx].utstyr.findIndex(u => u.id === itemId);
  if (aktiv) {
    if (existing >= 0) events[evIdx].utstyr[existing].antall = parseInt(antall)||1;
    else events[evIdx].utstyr.push({ id: itemId, antall: parseInt(antall)||1 });
  } else {
    if (existing >= 0) events[evIdx].utstyr.splice(existing, 1);
  }
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(ev.department);
  // Update usageCount on inventar item
  const items = readJSON(INVENTAR_FILE);
  const itemIdx = items.findIndex(i => i.id === itemId);
  if (itemIdx >= 0) {
    items[itemIdx].usageCount = events.filter(e => (e.utstyr||[]).some(u => u.id === itemId)).length;
    writeJSON(INVENTAR_FILE, items);
  }
  res.json({ ok: true });
});

// ── Reiserute per tur-event ───────────────────────────────────────
app.get("/api/events/:id/route", auth, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ err: "Ikke funnet" });
  res.json(ev.route || { days: [] });
});

// ── Geocoding proxy (unngår CORS og nettverksblokk fra klient) ────
app.get("/api/geocode/photon", auth, rateLimit(60, 60000), async function(req, res) {
  const q = (req.query.q || "").trim().slice(0, 200);
  if (!q) return res.json({ features: [] });
  try {
    const url = "https://photon.komoot.io/api/?q=" + encodeURIComponent(q) + "&limit=7&lang=no";
    const r = await fetch(url, {
      headers: {
        "User-Agent": "NAF-Events/1.0 (naf-events.no; contact@naf.no)",
        "Accept": "application/json",
        "Accept-Language": "no,nb;q=0.9,en;q=0.8",
        "Referer": "https://naf-events.no/"
      }
    });
    if (!r.ok) {
      console.error("[photon] HTTP " + r.status + " for q=" + q);
      return res.status(502).json({ error: "Photon feil " + r.status });
    }
    const d = await r.json();
    res.json(d);
  } catch(e) {
    res.status(502).json({ error: "Geocoding utilgjengelig" });
  }
});

app.get("/api/geocode/nominatim", auth, rateLimit(30, 60000), async function(req, res) {
  const q = (req.query.q || "").trim().slice(0, 200);
  if (!q) return res.json([]);
  try {
    const url = "https://nominatim.openstreetmap.org/search?format=json&limit=7&q=" + encodeURIComponent(q);
    const r = await fetch(url, {
      headers: {
        "User-Agent": "NAF-Events/1.0 (naf-events.no)",
        "Accept": "application/json",
        "Accept-Language": "no,nb;q=0.9"
      }
    });
    if (!r.ok) return res.status(502).json({ error: "Nominatim feil" });
    const d = await r.json();
    res.json(d);
  } catch(e) {
    res.status(502).json({ error: "Geocoding utilgjengelig" });
  }
});

// ── GPX-eksport ───────────────────────────────────────────────────
app.get("/api/events/:id/gpx", auth, rateLimit(20, 60000), async function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const ev = events.find(function(e) { return e.id === req.params.id; });
  if (!ev) return res.status(404).json({ error: "Ikke funnet" });
  if (ev.eventType !== "tur") return res.status(400).json({ error: "Kun tur-events støtter GPX" });

  const route = ev.route || { days: [] };
  const days  = route.days || [];

  // Manifest-modus: returner filliste uten å generere GPX
  if (req.query.manifest === "1") {
    const evTitle  = ev.title || "Tur";
    const baseSlug = evTitle.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    const files = [];
    if (days.length <= 1) {
      files.push({ id: "total", label: "📍 " + evTitle, filename: baseSlug + ".gpx", days: "all" });
    } else {
      files.push({ id: "total", label: "🗺️ Total – alle dager", filename: baseSlug + "-total.gpx", days: "all" });
      days.forEach(function(d, di) {
        const etapper   = d.etapper || [];
        const fra       = etapper[0] && etapper[0].fra ? etapper[0].fra : "";
        const lastE     = etapper[etapper.length - 1];
        const til       = lastE && lastE.til ? lastE.til : "";
        const routeDesc = fra && til ? fra + " → " + til : "Dag " + (di + 1);
        files.push({
          id:       "dag" + (di + 1),
          label:    "📅 Dag " + (di + 1) + (d.dato ? " (" + d.dato + ")" : "") + " – " + routeDesc,
          filename: baseSlug + "-dag" + (di + 1) + ".gpx",
          days:     di
        });
      });
    }
    return res.json({ files, multiDay: days.length > 1 });
  }

  // Download-modus: ?files=total,dag1,dag2 (kommaseparert) eller alle
  const requestedIds = req.query.files ? req.query.files.split(",") : ["all"];
  const downloadAll  = requestedIds.includes("all");

  function xmlEsc(s) {
    return (s || "").replace(/[<>&"]/g, function(c) {
      return { "<":"&lt;", ">":"&gt;", "&":"&amp;", '"':"&quot;" }[c];
    });
  }
  function sleep(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }

  async function geocode(name) {
    try {
      const url = "https://nominatim.openstreetmap.org/search?format=json&limit=1&q=" + encodeURIComponent(name);
      const r = await fetch(url, { headers: { "User-Agent": "EventsAdmin-GPX/1.0" } });
      const d = await r.json();
      if (d && d[0]) return { name, lat: parseFloat(d[0].lat), lon: parseFloat(d[0].lon) };
    } catch(e) {}
    return null;
  }

  async function fetchSegment(from, to, segProfile) {
    try {
      if (segProfile === "scenic" && process.env.GRAPHHOPPER_KEY) {
        const pts = "point=" + from.lat + "%2C" + from.lon + "&point=" + to.lat + "%2C" + to.lon;
        const r = await fetch("https://graphhopper.com/api/1/route?" + pts + "&profile=car&avoid=motorway&locale=no&calc_points=true&points_encoded=false&key=" + process.env.GRAPHHOPPER_KEY);
        const d = await r.json();
        if (d.paths && d.paths[0] && d.paths[0].points)
          return d.paths[0].points.coordinates.map(function(c) { return { lat: c[1], lon: c[0] }; });
      } else if (segProfile === "gravel") {
        const lonlats = from.lon + "," + from.lat + "|" + to.lon + "," + to.lat;
        const r = await fetch("https://brouter.de/brouter?lonlats=" + lonlats + "&profile=gravel&alternativeidx=0&format=geojson");
        const d = await r.json();
        if (d.features && d.features[0])
          return d.features[0].geometry.coordinates.map(function(c) { return { lat: c[1], lon: c[0] }; });
      } else {
        const osrmProf = segProfile === "foot" ? "foot" : "driving";
        const coordStr = from.lon + "," + from.lat + ";" + to.lon + "," + to.lat;
        const r = await fetch("https://router.project-osrm.org/route/v1/" + osrmProf + "/" + coordStr + "?overview=full&geometries=geojson");
        const d = await r.json();
        if (d.routes && d.routes[0])
          return d.routes[0].geometry.coordinates.map(function(c) { return { lat: c[1], lon: c[0] }; });
      }
    } catch(e) {}
    return [{ lat: from.lat, lon: from.lon }, { lat: to.lat, lon: to.lon }];
  }

  // Geocode alle unike steder
  const allNames = [];
  days.forEach(function(d) {
    (d.etapper || []).forEach(function(e) {
      if (e.fra && !allNames.includes(e.fra)) allNames.push(e.fra);
      if (e.til && !allNames.includes(e.til)) allNames.push(e.til);
    });
  });
  if (!allNames.length) return res.status(400).json({ error: "Ingen steder i ruten" });

  const coordCache = {};
  for (var i = 0; i < allNames.length; i++) {
    const result = await geocode(allNames[i]);
    if (result) coordCache[allNames[i]] = result;
    if (i < allNames.length - 1) await sleep(300);
  }

  // Hent rute-segmenter (cached per unik fra+til+profil)
  const segCache = {};
  const profileLabel = { driving:"Motorvei", scenic:"Landevei", gravel:"Grusveier" };
  for (var di = 0; di < days.length; di++) {
    var etapper = days[di].etapper || [];
    for (var ei = 0; ei < etapper.length; ei++) {
      var e = etapper[ei];
      var fra = coordCache[e.fra], til = coordCache[e.til];
      if (!fra || !til) continue;
      var prof = e.profile || "driving";
      var key  = e.fra + "||" + e.til + "||" + prof;
      if (!segCache[key]) { segCache[key] = await fetchSegment(fra, til, prof); await sleep(200); }
    }
  }

  // GPX builder
  function buildGpx(title, dayList) {
    var now = new Date().toISOString();
    var gpx = '<?xml version="1.0" encoding="UTF-8"?>\n';
    gpx += '<gpx version="1.1" creator="Events Admin" xmlns="http://www.topografix.com/GPX/1/1">\n';
    gpx += '  <metadata><name>' + xmlEsc(title) + '</name><time>' + now + '</time></metadata>\n';
    var seenWpt = {};
    dayList.forEach(function(d, dIdx) {
      (d.etapper || []).forEach(function(e, eIdx) {
        [[e.fra, eIdx === 0 && dIdx === 0 ? "start" : "wpt"],
         [e.til, e.type === "slutt" ? "end" : e.type === "hotell" ? "hotel" : "wpt"]
        ].forEach(function(pair) {
          var nm = pair[0], wt = pair[1];
          if (!nm || seenWpt[nm]) return;
          seenWpt[nm] = true;
          var c = coordCache[nm]; if (!c) return;
          var sym = wt === "start" ? "Flag, Green" : wt === "end" ? "Flag, Red" : wt === "hotel" ? "Lodging" : "Waypoint";
          gpx += '  <wpt lat="' + c.lat.toFixed(6) + '" lon="' + c.lon.toFixed(6) + '">\n';
          gpx += '    <name>' + xmlEsc(nm) + '</name><sym>' + sym + '</sym>\n';
          gpx += '  </wpt>\n';
        });
      });
    });
    dayList.forEach(function(d, dIdx) {
      (d.etapper || []).forEach(function(e, eIdx) {
        var fra = coordCache[e.fra], til = coordCache[e.til]; if (!fra || !til) return;
        var prof = e.profile || "driving";
        var key  = e.fra + "||" + e.til + "||" + prof;
        var pts  = segCache[key] || [{ lat: fra.lat, lon: fra.lon }, { lat: til.lat, lon: til.lon }];
        var sn   = xmlEsc(title + " – etappe " + (eIdx + 1) + " (" + (profileLabel[prof] || prof) + ")");
        gpx += '  <trk><name>' + sn + '</name><trkseg>\n';
        pts.forEach(function(pt) { gpx += '    <trkpt lat="' + pt.lat.toFixed(6) + '" lon="' + pt.lon.toFixed(6) + '"/>\n'; });
        gpx += '  </trkseg></trk>\n';
      });
    });
    gpx += '</gpx>';
    return gpx;
  }

  var evTitle  = ev.title || "Tur";
  var baseSlug = evTitle.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

  // Én dag eller kun én fil: send direkte som GPX
  if (days.length <= 1 || (requestedIds.length === 1 && !downloadAll)) {
    var singleDayIdx = requestedIds[0] === "total" || downloadAll ? null : parseInt(requestedIds[0].replace("dag","")) - 1;
    var singleDays   = singleDayIdx != null && !isNaN(singleDayIdx) ? [days[singleDayIdx]] : days;
    var singleTitle  = singleDayIdx != null && !isNaN(singleDayIdx)
      ? evTitle + " – Dag " + (singleDayIdx + 1) + (days[singleDayIdx] && days[singleDayIdx].dato ? " (" + days[singleDayIdx].dato + ")" : "")
      : evTitle;
    var gpxSingle = buildGpx(singleTitle, singleDays.filter(Boolean));
    var fnSingle  = singleDayIdx != null && !isNaN(singleDayIdx) ? baseSlug + "-dag" + (singleDayIdx+1) + ".gpx" : baseSlug + ".gpx";
    res.setHeader("Content-Type", "application/gpx+xml");
    res.setHeader("Content-Disposition", 'attachment; filename="' + fnSingle + '"');
    return res.send(gpxSingle);
  }

  // Flerdag: bygg ZIP med kun valgte filer
  var files = [];
  if (downloadAll || requestedIds.includes("total")) {
    files.push({ name: baseSlug + "-total.gpx", data: Buffer.from(buildGpx(evTitle + " – Total", days), "utf8") });
  }
  days.forEach(function(d, di) {
    var fileId = "dag" + (di + 1);
    if (!downloadAll && !requestedIds.includes(fileId)) return;
    var dayLabel = evTitle + " – Dag " + (di + 1) + (d.dato ? " (" + d.dato + ")" : "");
    files.push({ name: baseSlug + "-dag" + (di + 1) + ".gpx", data: Buffer.from(buildGpx(dayLabel, [d]), "utf8") });
  });

  // Kun én fil valgt: send direkte
  if (files.length === 1) {
    res.setHeader("Content-Type", "application/gpx+xml");
    res.setHeader("Content-Disposition", 'attachment; filename="' + files[0].name + '"');
    return res.send(files[0].data);
  }

  function makeZip(fileList) {
    var crc32Table = (function() {
      var t = new Uint32Array(256);
      for (var i = 0; i < 256; i++) {
        var cx = i;
        for (var j = 0; j < 8; j++) cx = (cx & 1) ? (0xEDB88320 ^ (cx >>> 1)) : (cx >>> 1);
        t[i] = cx;
      }
      return t;
    })();
    function crc32(buf) { var c = 0xFFFFFFFF; for (var i = 0; i < buf.length; i++) c = crc32Table[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
    function u16(b, o, v) { b[o] = v & 0xFF; b[o+1] = (v >> 8) & 0xFF; }
    function u32(b, o, v) { b[o]=v&0xFF; b[o+1]=(v>>8)&0xFF; b[o+2]=(v>>16)&0xFF; b[o+3]=(v>>24)&0xFF; }
    var parts = [], central = [], offset = 0;
    fileList.forEach(function(f) {
      var nb = Buffer.from(f.name, "utf8"), data = f.data, crc = crc32(data);
      var now2 = new Date();
      var dt = ((now2.getFullYear()-1980)<<9)|((now2.getMonth()+1)<<5)|now2.getDate();
      var tm = (now2.getHours()<<11)|(now2.getMinutes()<<5)|Math.floor(now2.getSeconds()/2);
      var lfh = Buffer.alloc(30 + nb.length);
      u32(lfh,0,0x04034b50); u16(lfh,4,20); u16(lfh,6,0); u16(lfh,8,0);
      u16(lfh,10,tm); u16(lfh,12,dt); u32(lfh,14,crc); u32(lfh,18,data.length); u32(lfh,22,data.length);
      u16(lfh,26,nb.length); u16(lfh,28,0); nb.copy(lfh,30);
      central.push({ nb, crc, size: data.length, dt, tm, offset });
      parts.push(lfh, data); offset += lfh.length + data.length;
    });
    var cdStart = offset;
    central.forEach(function(e) {
      var cde = Buffer.alloc(46 + e.nb.length);
      u32(cde,0,0x02014b50); u16(cde,4,20); u16(cde,6,20); u16(cde,8,0); u16(cde,10,0);
      u16(cde,12,e.tm); u16(cde,14,e.dt); u32(cde,16,e.crc); u32(cde,20,e.size); u32(cde,24,e.size);
      u16(cde,28,e.nb.length); u16(cde,30,0); u16(cde,32,0); u16(cde,34,0); u16(cde,36,0);
      u32(cde,38,0); u32(cde,42,e.offset); e.nb.copy(cde,46);
      parts.push(cde); offset += cde.length;
    });
    var eocd = Buffer.alloc(22);
    u32(eocd,0,0x06054b50); u16(eocd,4,0); u16(eocd,6,0);
    u16(eocd,8,fileList.length); u16(eocd,10,fileList.length);
    u32(eocd,12,offset-cdStart); u32(eocd,16,cdStart); u16(eocd,20,0);
    parts.push(eocd);
    return Buffer.concat(parts);
  }

  var zipBuf = makeZip(files);
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", 'attachment; filename="' + baseSlug + '-gpx.zip"');
  res.send(zipBuf);
});

app.put("/api/events/:id/route", auth, managerOrAdmin, function(req, res) {
  const events = readJSON(EVENTS_FILE);
  const i = events.findIndex(e => e.id === req.params.id);
  if (i === -1) return res.status(404).json({ err: "Ikke funnet" });
  const days = Array.isArray(req.body.days) ? req.body.days.slice(0, 30) : [];
  // Sanitér
  const clean = days.map(d => ({
    dato: (d.dato || "").slice(0, 10),
    etapper: Array.isArray(d.etapper) ? d.etapper.slice(0, 50).map(e => ({
      type:    ["start","stopp","lunsj","middag","hotell","slutt","bensin","opplevelse"].includes(e.type) ? e.type : "stopp",
      fra:     (e.fra   || "").trim().slice(0, 200),
      til:     (e.til   || "").trim().slice(0, 200),
      km:      e.km != null && e.km !== "" ? parseFloat(e.km) || null : null,
      tid:     e.tid != null && e.tid !== "" ? parseFloat(e.tid) || null : null,
      notat:   (e.notat || "").trim().slice(0, 500),
      profile: ["driving","scenic","gravel","foot"].includes(e.profile) ? e.profile : "driving",
      opplevelseSubtype: e.type === "opplevelse" && ["museum","natur","utsikt","historisk","aktivitet","kultur","mat","annet"].includes(e.opplevelseSubtype) ? e.opplevelseSubtype : (e.type === "opplevelse" ? "annet" : undefined),
      // Behold geocodede koordinater for minikartet
      _lat:     typeof e._lat     === "number" ? e._lat     : undefined,
      _lon:     typeof e._lon     === "number" ? e._lon     : undefined,
      _fra_lat: typeof e._fra_lat === "number" ? e._fra_lat : undefined,
      _fra_lon: typeof e._fra_lon === "number" ? e._fra_lon : undefined,
    })) : [],
  }));
  events[i].route = { days: clean };
  // Lagre ruteprofil direkte på eventet
  const validProfiles = ["driving","scenic","gravel","foot"];
  const profile = req.body.routeProfile;
  if (profile && validProfiles.includes(profile)) events[i].routeProfile = profile;
  writeJSON(EVENTS_FILE, events);
  broadcastEventUpdate(events[i].department);
  res.json({ ok: true });
});

// ── AI: Generer turforslag ────────────────────────────────────────
app.post("/api/ai/generate-route", auth, managerOrAdmin, rateLimit(10, 60000), async function(req, res) {
  const { start, direction, distanceKm, profile, roundtrip, attempt,
          startDate, endDate, startTime, endTime, numDays } = req.body;
  if (!start || !distanceKm) return res.status(400).json({ error: "Mangler startsted eller avstand" });

  const days = Math.max(1, Math.min(14, parseInt(numDays) || 1));
  const isMultiday = days > 1;

  const fmtDate = function(d, t) {
    if (!d) return "";
    const dt = new Date(d);
    const ds = dt.toLocaleDateString("nb-NO", { weekday:"long", day:"numeric", month:"long", year:"numeric" });
    return t ? ds + " kl. " + t : ds;
  };
  const startDateDesc = startDate ? fmtDate(startDate, startTime) : "";
  const endDateDesc   = endDate   ? fmtDate(endDate,   endTime)   : "";

  const profileMap = {
    scenic:  { name: "LANDEVEI",     desc: "kun landeveier og riksveier – INGEN motorveier, INGEN grusveier. Velg pittoreske ruter, kystveier, fjellveier og sekundærveier." },
    driving: { name: "MOTORVEI",     desc: "primært motorveier og hovedveier for effektiv kjøring." },
    gravel:  { name: "GRUS/OFFROAD", desc: "grusveier, skogsveier og offroad-strekninger – unngå asfalt der mulig." },
  };
  const chosenProfile = profileMap[profile] || profileMap.scenic;
  const usedProfile   = ["driving","scenic","gravel"].includes(profile) ? profile : "scenic";

  // Cardinal direction → compass bearing + strict geographic constraint
  const dirBearing = { nord:"nord", nordøst:"nordøst", øst:"øst", sørøst:"sørøst", sør:"sør", sørvest:"sørvest", vest:"vest", nordvest:"nordvest" };
  const dirBlock = {
    nord:    "ABSOLUTT KRAV: Kjør NORDOVER fra " + start + ". Alle steder MÅ ha høyere breddegrad (latitude) enn " + start + ". Tenk: Hamar, Lillehammer, Trondheim-retning fra Oslo. ALDRI sørover.",
    nordøst: "ABSOLUTT KRAV: Kjør NORDØST fra " + start + ". Alle steder MÅ ligge nordøst. Tenk: Sverige-grensen, Halden, Fredrikstad-retning er FEIL – velg Elverum, Kongsvinger, Charlottenberg.",
    øst:     "ABSOLUTT KRAV: Kjør ØSTOVER fra " + start + ". Alle steder MÅ ligge øst – mot Sverige. Ingen steder vestover, ingen steder nordover. Tenk: Kongsvinger, Arvika, Karl stad.",
    sørøst:  "ABSOLUTT KRAV: Kjør SØRØST fra " + start + ". Alle steder MÅ ligge sørøst. Tenk: Fredrikstad, Sarpsborg, Halden, Strömstad.",
    sør:     "ABSOLUTT KRAV: Kjør SØROVER fra " + start + ". Alle steder MÅ ha lavere breddegrad (latitude) enn " + start + ". Tenk: Drammen, Larvik, Kristiansand-retning fra Oslo. ALDRI nordover.",
    sørvest: "ABSOLUTT KRAV: Kjør SØRVEST fra " + start + ". Alle steder MÅ ligge sørvest. Tenk: Drammen, Kongsberg, Skien, Porsgrunn.",
    vest:    "ABSOLUTT KRAV: Kjør VESTOVER fra " + start + ". Alle steder MÅ ligge vest – mot kysten. Ingen steder østover. Tenk: Hønefoss, Tyrifjorden, Geilo, Flåm.",
    nordvest:"ABSOLUTT KRAV: Kjør NORDVEST fra " + start + ". Alle steder MÅ ligge nordvest. Tenk: Ringerike, Norefjell, Geilo-retning.",
  };
  const directionEnforcement = direction ? (dirBlock[direction] || "") : "";

  if (MOCK_AI) {
    const mockDays = [];
    for (let i = 0; i < days; i++) {
      const dato = startDate ? (function(){ const d = new Date(startDate); d.setDate(d.getDate()+i); return d.toISOString().slice(0,10); })() : "";
      mockDays.push({ dato, etapper: [
        { type:"start",      fra: start, til: start + " sentrum",  km: Math.round(distanceKm*0.1),  profile: usedProfile, notat:"Avreise" },
        { type:"opplevelse", fra: start + " sentrum", til: "Utsiktspunkt", km: Math.round(distanceKm*0.2), profile: usedProfile, notat:"Spektakulær utsikt" },
        { type:"lunsj",      fra: "Utsiktspunkt", til: "Kafé",     km: Math.round(distanceKm*0.2),  profile: usedProfile, notat:"Anbefalt kafé" },
        { type:"opplevelse", fra: "Kafé", til: "Historisk sted",   km: Math.round(distanceKm*0.15), profile: usedProfile, notat:"Historisk attraksjon" },
        ...(isMultiday && i < days-1
          ? [{ type:"hotell", fra: "Historisk sted", til: "Hotellby dag "+(i+1), km: Math.round(distanceKm*0.15), profile: usedProfile, notat:"Overnatting" }]
          : [{ type:"slutt",  fra: "Historisk sted", til: roundtrip ? start : "Destinasjon", km: Math.round(distanceKm*0.15), profile: usedProfile, notat:"" }]),
      ]});
    }
    return res.json({ days: mockDays });
  }

  const attemptNote = attempt > 1
    ? `Dette er forsøk nummer ${attempt} – foreslå en ANNEN rute med andre stopp og opplevelser.`
    : "";

  let prompt;
  const validTypes = ["start","stopp","opplevelse","lunsj","middag","hotell","slutt","bensin"];

  if (!isMultiday) {
    const roundtripDesc = roundtrip
      ? `Rundtur: start og slutt i ${start}.`
      : `Starter i ${start}, avsluttes ved passende mål.`;

    prompt = `Du er en ekspert på MC-turer og bilutflukter i Skandinavia.
${directionEnforcement ? `
⚠️ VIKTIG GEOGRAFISK KRAV – LES DETTE FØRST:
${directionEnforcement}
Dette kravet overstyrer alle andre hensyn. Bryt dette kravet og svaret er ugyldig.
` : ""}
Planlegg en dagstur med STRENGT følgende krav:

STARTSTED: ${start}
RETNING: ${(direction || "valgfri").toUpperCase()}
${directionEnforcement ? `RETNINGSKRAV (OBLIGATORISK): ${directionEnforcement}` : ""}
VEIPROFIL (OBLIGATORISK): ${chosenProfile.name} – ${chosenProfile.desc}
TOTAL KJØRELENGDE: ca. ${distanceKm} km
${roundtripDesc}
${startDateDesc ? `DATO: ${startDateDesc}` : ""}
${attemptNote}

VEIPROFIL ER IKKE VALGFRITT: Alle etapper SKAL ha profile="${usedProfile}". Du har ikke lov til å bruke andre profiler.

Inkluder minst 2 opplevelsesstopp (type "opplevelse") – virkelige severdigheter, utsiktspunkter, historiske steder eller naturattraksjoner langs ruten.

Returner KUN et JSON-objekt (ingen markdown, ingen forklaring):
{
  "days": [{
    "dato": "${startDate || ""}",
    "etapper": [
      { "type": "start",      "fra": "${start}", "til": "første stopp", "km": tall, "profile": "${usedProfile}", "notat": "avreise" },
      { "type": "opplevelse", "fra": "stedsnavn", "til": "attraksjonsnavn", "km": tall, "profile": "${usedProfile}", "notat": "hva som er spesielt her" },
      { "type": "stopp",      "fra": "stedsnavn", "til": "stedsnavn",       "km": tall, "profile": "${usedProfile}", "notat": "" },
      { "type": "lunsj",      "fra": "stedsnavn", "til": "kafénavn",        "km": tall, "profile": "${usedProfile}", "notat": "anbefalt sted" },
      { "type": "opplevelse", "fra": "stedsnavn", "til": "attraksjonsnavn", "km": tall, "profile": "${usedProfile}", "notat": "hva som er spesielt" },
      { "type": "slutt",      "fra": "stedsnavn", "til": "${roundtrip ? start : "destinasjon"}", "km": tall, "profile": "${usedProfile}", "notat": "" }
    ]
  }]
}

Absolutte regler:
- profile MÅ være "${usedProfile}" på ALLE etapper uten unntak
- ${directionEnforcement || ("Ruten skal gå mot " + (direction || "valgfri retning"))}
- Bruk virkelige stedsnavn som kan geocodes i Skandinavia
- 5-7 etapper totalt, km summerer til ca. ${distanceKm}
- Minst 2 "opplevelse"-etapper med virkelige attraksjoner og beskrivende notat
- For type "opplevelse": legg til "opplevelseSubtype" – velg én av: museum, natur, utsikt, historisk, aktivitet, kultur, mat, annet
- notat maks 80 tegn
- Kun JSON, ingen annen tekst`;

  } else {
    const lastDayDesc = roundtrip ? `Siste dag: returner til ${start}.` : "Siste dag: avslutt ved passende mål.";
    const dayDates = [];
    for (let i = 0; i < days; i++) {
      if (startDate) { const d = new Date(startDate); d.setDate(d.getDate()+i); dayDates.push(d.toISOString().slice(0,10)); }
      else dayDates.push("");
    }
    const daySchema = dayDates.map(function(dato, i) {
      const isFirst = i === 0, isLast = i === days-1;
      return `    {
      "dato": "${dato}",
      "etapper": [
        { "type": "${isFirst ? "start" : "stopp"}", "fra": "${isFirst ? start : "hotellby dag "+i}", "til": "...", "km": tall, "profile": "${usedProfile}", "notat": "..." },
        { "type": "opplevelse", "fra": "...", "til": "attraksjonsnavn", "km": tall, "profile": "${usedProfile}", "notat": "hva som er spesielt" },
        { "type": "lunsj", "fra": "...", "til": "kafénavn", "km": tall, "profile": "${usedProfile}", "notat": "anbefalt sted" },
        { "type": "opplevelse", "fra": "...", "til": "attraksjonsnavn", "km": tall, "profile": "${usedProfile}", "notat": "..." },
        { "type": "${isLast ? "slutt" : "hotell"}", "fra": "...", "til": "${isLast ? (roundtrip ? start : "destinasjon") : "hotellby"}", "km": tall, "profile": "${usedProfile}", "notat": "${isLast ? "" : "overnatting"}" }
      ]
    }`;
    }).join(",\n");

    prompt = `Du er en ekspert på MC-turer og bilutflukter i Skandinavia.
${directionEnforcement ? `
⚠️ VIKTIG GEOGRAFISK KRAV – LES DETTE FØRST:
${directionEnforcement}
Dette kravet overstyrer alle andre hensyn. Bryt dette kravet og svaret er ugyldig.
` : ""}
Planlegg en ${days}-dagers tur med STRENGT følgende krav:

STARTSTED: ${start}
RETNING: ${(direction || "valgfri").toUpperCase()}
${directionEnforcement ? `RETNINGSKRAV (OBLIGATORISK): ${directionEnforcement}` : ""}
VEIPROFIL (OBLIGATORISK): ${chosenProfile.name} – ${chosenProfile.desc}
KM PER DAG: ca. ${distanceKm} km, ANTALL DAGER: ${days}
${startDateDesc ? `AVREISE: ${startDateDesc}` : ""}${endDateDesc ? `\nHJEMKOMST: ${endDateDesc}` : ""}
${lastDayDesc}
${attemptNote}

VEIPROFIL ER IKKE VALGFRITT: Alle etapper SKAL ha profile="${usedProfile}". Du har ikke lov til å bruke andre profiler.

For hver dag:
- Minst 2 opplevelsesstopp (type "opplevelse") – virkelige severdigheter, utsiktspunkter, historiske steder
- Lunsj-stopp hver dag
- Dag 2+ starter fra hotellet forrige dag (IKKE fra ${start})
- Hotell på alle dager unntatt siste – velg virkelige byer/tettsteder

Returner KUN et JSON-objekt:
{
  "days": [
${daySchema}
  ]
}

Absolutte regler:
- profile MÅ være "${usedProfile}" på ALLE etapper uten unntak
- ${directionEnforcement || ("Ruten skal gå mot " + (direction || "valgfri retning"))}
- Bruk virkelige stedsnavn som kan geocodes i Skandinavia
- 5-7 etapper per dag, minst 2 "opplevelse" per dag
- For type "opplevelse": legg til "opplevelseSubtype" – velg én av: museum, natur, utsikt, historisk, aktivitet, kultur, mat, annet
- notat maks 80 tegn
- Kun JSON, ingen annen tekst`;
  }

  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": process.env.ANTHROPIC_API_KEY },
      body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: isMultiday ? 4000 : 1500, messages: [{ role: "user", content: prompt }] })
    });
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: data.error?.message || "AI-feil" });
    const text = (data.content || []).map(b => b.text || "").join("").trim()
      .replace(/^```json\s*/i,"").replace(/^```\s*/,"").replace(/```$/,"").trim();
    let parsed;
    try { parsed = JSON.parse(text); } catch(e) {
      return res.status(500).json({ error: "Kunne ikke tolke AI-svar", raw: text.slice(0,200) });
    }
    const validTypes = ["start","stopp","opplevelse","lunsj","middag","hotell","slutt","bensin"];
    const resultDays = Array.isArray(parsed.days) ? parsed.days.slice(0,14).map(function(d, i) {
      const dato = d.dato || (startDate ? (function(){ const dt = new Date(startDate); dt.setDate(dt.getDate()+i); return dt.toISOString().slice(0,10); })() : "");
      return {
        dato,
        etapper: Array.isArray(d.etapper) ? d.etapper.slice(0,12).map(function(e) { return {
          type:    validTypes.includes(e.type) ? e.type : "stopp",
          fra:     (e.fra   || "").trim().slice(0,200),
          til:     (e.til   || "").trim().slice(0,200),
          km:      e.km != null ? parseFloat(e.km) || null : null,
          notat:   (e.notat || "").trim().slice(0,80),
          profile: usedProfile, // enforce chosen profile, ignore AI's per-etappe choice
          opplevelseSubtype: e.type === "opplevelse" && ["museum","natur","utsikt","historisk","aktivitet","kultur","mat","annet"].includes(e.opplevelseSubtype) ? e.opplevelseSubtype : (e.type === "opplevelse" ? e.opplevelseSubtype || "annet" : undefined),
        }; }) : []
      };
    }) : [];
    res.json({ days: resultDays });
  } catch(e) {
    res.status(500).json({ error: "Nettverksfeil mot AI: " + e.message });
  }
});

app.get("*", function(req, res) {
  res.sendFile(path.join(__dirname, "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log("naf-events running on port " + PORT);
  // Migrasjon: normaliser roller til lowercase_underscore
  try {
    const users = readJSON(USERS_FILE);
    let changed = 0;
    users.forEach(function(u) {
      if (u.role) {
        const norm = u.role.toLowerCase().replace(/[- ]/g,"_");
        if (norm !== u.role) { u.role = norm; changed++; }
      }
      // Normaliser roller i accessList også
      (u.accessList||[]).forEach(function(a) {
        if (a.role) {
          const norm = a.role.toLowerCase().replace(/[- ]/g,"_");
          if (norm !== a.role) { a.role = norm; changed++; }
        }
      });
    });
    if (changed > 0) { writeJSON(USERS_FILE, users); console.log("[migrate] Normaliserte " + changed + " roller"); }
  } catch(e) { console.error("[migrate] Feil ved rolenormalisering:", e.message); }
});
