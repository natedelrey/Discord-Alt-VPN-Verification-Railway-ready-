import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import pg from "pg";
import cookieParser from "cookie-parser";

const {
  PORT = 8080,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT,
  API_SECRET = "supersecret",
  DATABASE_URL,
  GUILD_ID
} = process.env;

if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT || !DATABASE_URL || !GUILD_ID) {
  console.error("[web] Missing env vars. Check .env.example");
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: DATABASE_URL });

const app = express();
app.use(cookieParser());

// ---- helpers ----
function hmacHex(txt) {
  return crypto.createHmac("sha256", API_SECRET).update(txt).digest("hex");
}

function signPayload(payloadObj) {
  const body = JSON.stringify(payloadObj);
  return hmacHex(body);
}

function verifySig({ g, u, s }) {
  const expected = signPayload({ g, u });
  try {
    return crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected));
  } catch {
    return false;
  }
}

function networkKey(ip) {
  // Simple /24 (IPv4) or ~ /48 (IPv6)
  if (ip.includes(":")) {
    return ip.split(":").slice(0, 3).join(":");
  } else {
    const parts = ip.split(".");
    if (parts.length !== 4) return ip;
    parts[3] = "0";
    return parts.join(".");
  }
}

// Stub VPN risk scorer — swap with a real provider later
async function vpnRisk(ip) {
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.")
  ) return 0;
  return 35; // pretend normal risk by default
}

// Ensure schema on boot (safe to run repeatedly)
async function ensureSchema() {
  const sql = `
    CREATE TABLE IF NOT EXISTS verifications (
      guild_id        TEXT NOT NULL,
      user_id         TEXT NOT NULL,
      verified        BOOLEAN DEFAULT FALSE,
      network_hash    TEXT,
      ip_risk_score   NUMERIC,
      fingerprint_id  TEXT,
      created_at      TIMESTAMP DEFAULT NOW(),
      granted_at      TIMESTAMP,
      PRIMARY KEY (guild_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS verifications_guild_network_idx
      ON verifications (guild_id, network_hash);
    CREATE INDEX IF NOT EXISTS verifications_pending_idx
      ON verifications (guild_id, verified, granted_at);
  `;
  await pool.query(sql);
}
ensureSchema().catch(e => {
  console.error("[web] schema init failed", e);
  process.exit(1);
});

// ---- routes ----

// Step 1: entry from bot DM link
app.get("/v", async (req, res) => {
  const { g, u, s } = req.query;
  if (!g || !u || !s || !verifySig({ g, u, s })) {
    return res.status(400).send("invalid or expired token");
  }

  const state = signPayload({ g, u, n: crypto.randomBytes(8).toString("hex") });
  const url = new URL("https://discord.com/api/oauth2/authorize");
  url.searchParams.set("client_id", DISCORD_CLIENT_ID);
  url.searchParams.set("redirect_uri", DISCORD_REDIRECT);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "identify");
  url.searchParams.set("state", state);
  res.redirect(url.toString());
});

// Step 2: OAuth callback → store network/hash → mark verified or deny
app.get("/callback", async (req, res) => {
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "0.0.0.0";

  const code = req.query.code;
  if (!code) return res.status(400).send("missing code");

  // Exchange code
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: DISCORD_REDIRECT
    })
  });
  if (!tokenRes.ok) {
    return res.status(400).send("oauth error");
  }
  const tokens = await tokenRes.json();

  // Fetch identity
  const meRes = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${tokens.access_token}` }
  });
  if (!meRes.ok) return res.status(400).send("oauth user error");
  const me = await meRes.json();
  const userId = me.id;

  // Compute network/risk
  const net = networkKey(ip);
  const netHash = hmacHex(`${GUILD_ID}:${net}`);
  const risk = await vpnRisk(ip);

  // Re-use check
  const { rows: reuse } = await pool.query(
    `SELECT user_id FROM verifications
     WHERE guild_id=$1 AND network_hash=$2 AND verified=true AND user_id<>$3
     LIMIT 1`,
    [GUILD_ID, netHash, userId]
  );
  if (reuse.length > 0) {
    await pool.query(
      `INSERT INTO verifications(guild_id,user_id,verified,network_hash,ip_risk_score,granted_at)
       VALUES ($1,$2,false,$3,$4,NULL)
       ON CONFLICT (guild_id,user_id) DO UPDATE
         SET verified=false, network_hash=$3, ip_risk_score=$4, granted_at=NULL`,
      [GUILD_ID, userId, netHash, risk]
    );
    return res.status(403).send("denied: network already used by another account");
  }

  // Risk threshold (tune as needed)
  if (risk >= 75) {
    await pool.query(
      `INSERT INTO verifications(guild_id,user_id,verified,network_hash,ip_risk_score,granted_at)
       VALUES ($1,$2,false,$3,$4,NULL)
       ON CONFLICT (guild_id,user_id) DO UPDATE
         SET verified=false, network_hash=$3, ip_risk_score=$4, granted_at=NULL`,
      [GUILD_ID, userId, netHash, risk]
    );
    return res.status(403).send("denied: vpn/proxy risk too high");
  }

  await pool.query(
    `INSERT INTO verifications(guild_id,user_id,verified,network_hash,ip_risk_score)
     VALUES ($1,$2,true,$3,$4)
     ON CONFLICT (guild_id,user_id) DO UPDATE
       SET verified=true, network_hash=$3, ip_risk_score=$4`,
    [GUILD_ID, userId, netHash, risk]
  );

  res.send("verified ✨ you can close this tab.");
});

// health
app.get("/health", (_, res) => res.send("ok"));

app.listen(PORT, () => console.log(`[web] listening on :${PORT}`));
