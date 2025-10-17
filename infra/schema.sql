-- Core table
CREATE TABLE IF NOT EXISTS verifications (
  guild_id        TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  verified        BOOLEAN DEFAULT FALSE,
  network_hash    TEXT,
  ip_risk_score   NUMERIC,
  fingerprint_id  TEXT,
  created_at      TIMESTAMP DEFAULT NOW(),
  granted_at      TIMESTAMP, -- when the bot granted the role (null means pending)
  PRIMARY KEY (guild_id, user_id)
);

-- Speed up network re-use checks
CREATE INDEX IF NOT EXISTS verifications_guild_network_idx
  ON verifications (guild_id, network_hash);

-- Pending grant queue
CREATE INDEX IF NOT EXISTS verifications_pending_idx
  ON verifications (guild_id, verified, granted_at);
