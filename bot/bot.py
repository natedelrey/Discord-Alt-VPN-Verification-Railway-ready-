import os, json, hmac, hashlib, asyncio, asyncpg
import discord
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = int(os.getenv("GUILD_ID", "0"))
VERIFIED_ROLE_ID = int(os.getenv("VERIFIED_ROLE_ID", "0"))
VERIFY_BASE = os.getenv("VERIFY_BASE", "https://yourdomain.com/v")
API_SECRET = os.getenv("API_SECRET", "supersecret")
DATABASE_URL = os.getenv("DATABASE_URL")

intents = discord.Intents.default()
intents.members = True  # enable in Dev Portal too
bot = commands.Bot(command_prefix="!", intents=intents)

# ---- db ----
pool: asyncpg.Pool | None = None

SCHEMA_SQL = """
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
"""

async def init_db():
  global pool
  pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)
  async with pool.acquire() as con:
    await con.execute(SCHEMA_SQL)

# ---- helpers ----
def sign(payload: dict) -> str:
  body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
  return hmac.new(API_SECRET.encode(), body, hashlib.sha256).hexdigest()

def verify_link_for(member: discord.Member) -> str:
  payload = {"g": str(member.guild.id), "u": str(member.id)}
  s = sign(payload)
  return f"{VERIFY_BASE}?g={payload['g']}&u={payload['u']}&s={s}"

# ---- events ----
@bot.event
async def on_ready():
  print(f"[bot] Logged in as {bot.user}")
  await init_db()
  poll_grants.start()

@bot.event
async def on_member_join(member: discord.Member):
  if member.guild.id != GUILD_ID or member.bot:
    return
  url = verify_link_for(member)
  msg = (
    f"hey {member.mention} ✨ tap to verify: {url}\n"
    "we use IP/network checks to prevent alts & VPN abuse."
  )
  try:
    await member.send(msg)
  except Exception:
    # fallback: try posting in a #verify channel if you want
    pass

# ---- background: grant roles for verified users ----
@tasks.loop(seconds=10)
async def poll_grants():
  await bot.wait_until_ready()
  guild = bot.get_guild(GUILD_ID)
  if not guild:
    return

  role = guild.get_role(VERIFIED_ROLE_ID)
  if not role:
    return

  async with pool.acquire() as con:
    rows = await con.fetch(
      """
      SELECT user_id FROM verifications
      WHERE guild_id = $1 AND verified = true AND granted_at IS NULL
      LIMIT 25
      """,
      str(GUILD_ID),
    )

    for r in rows:
      user_id = int(r["user_id"])
      member = guild.get_member(user_id) or await guild.fetch_member(user_id)
      if not member:
        continue
      try:
        await member.add_roles(role, reason="Passed external verification")
        await con.execute(
          "UPDATE verifications SET granted_at = NOW() WHERE guild_id=$1 AND user_id=$2",
          str(GUILD_ID), str(user_id)
        )
      except Exception as e:
        print("[bot] grant error:", e)

# manual command if needed
@bot.command()
@commands.has_permissions(manage_roles=True)
async def grant(ctx, member: discord.Member):
  role = ctx.guild.get_role(VERIFIED_ROLE_ID)
  await member.add_roles(role, reason="Manual grant")
  await ctx.reply(f"Granted Verified to {member.mention}")

bot.run(TOKEN)
