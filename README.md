# Discord Alt/VPN Verification (Railway-ready)

Blocks obvious alts/VPNs by **external web verify**:
1. Bot DMs a link → user OAuths on web
2. Web records IP → hashes network (/24 or /48) with HMAC
3. If network reused by another verified user or VPN risk high → deny
4. If pass → mark verified in DB
5. Bot polls DB and auto-grants **Verified** role

## Deploy on Railway

### 1) Create a Postgres plugin
- Add → **PostgreSQL**
- Copy the `DATABASE_URL` (you’ll attach it to both services)

### 2) Create Web service
- New → **Deploy from GitHub** → pick this repo
- Service Settings → **Root Directory** = `web`
- Variables:
  - `DATABASE_URL` = (Postgres plugin)
  - `API_SECRET` = same as bot
  - `DISCORD_CLIENT_ID` = your app ID
  - `DISCORD_CLIENT_SECRET` = your bot secret
  - `DISCORD_REDIRECT` = `https://<web-subdomain>.up.railway.app/callback`
  - `GUILD_ID` = your guild id
- Note the web URL → `https://<subdomain>.up.railway.app`

### 3) Create Bot service
- New → **Deploy from GitHub** → same repo
- Root Directory = `bot`
- Variables:
  - `BOT_TOKEN` = your bot token
  - `GUILD_ID` = your guild id
  - `VERIFIED_ROLE_ID` = role to grant
  - `VERIFY_BASE` = `https://<web-subdomain>.up.railway.app/v`
  - `API_SECRET` = same as web
  - `DATABASE_URL` = (Postgres plugin)

### 4) Discord portal
- **Bot → Privileged Intents**: enable **Server Members Intent**
- **OAuth2 → Redirects**: add the web `DISCORD_REDIRECT` URL
- Invite bot with permissions to **View Members** and **Manage Roles**

## Customize

- Swap real VPN scoring in `web/server.js` (`vpnRisk(ip)`).
- Tune reuse / thresholds (e.g., allow reuse after 30 days).
- Add a whitelist table / staff bypass if needed.

## Privacy

We don’t store raw IPs. We store `HMAC(secret, guild_id:network-prefix)` only.
Change `API_SECRET` anytime to rotate the hash salt.
