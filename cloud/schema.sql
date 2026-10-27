-- Prodify Cloud database (Cloudflare D1). The server only stores encrypted objects: names are hashes and
-- contents are encrypted by the app before upload, so it can't read anyone's notes.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  plan TEXT NOT NULL DEFAULT 'free',   -- free | basic | pro
  used INTEGER NOT NULL DEFAULT 0,     -- bytes stored
  seq INTEGER NOT NULL DEFAULT 0,      -- bumped on every change; devices ask for changes since their last seq
  created INTEGER NOT NULL
);

-- One-time sign-in codes (6 digits, 10 minutes, 5 tries). Only a hash of email + code is kept.
CREATE TABLE IF NOT EXISTS codes (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires INTEGER NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL
);

-- Signed-in devices. Only a hash of each session token is kept.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device TEXT NOT NULL DEFAULT '',
  created INTEGER NOT NULL,
  last_used INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);

-- The index of each user's objects; the bytes live in R2 under "<user id>/<object id>".
-- Object ids: "account" (the account file with the locked data key), "r/<hash>" (a note, task list…),
-- "a/<name>" (a photo or PDF). Deleted objects stay as tombstones so other devices learn about the delete.
CREATE TABLE IF NOT EXISTS objects (
  user_id TEXT NOT NULL,
  id TEXT NOT NULL,
  rev INTEGER NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0,
  seq INTEGER NOT NULL,
  updated INTEGER NOT NULL,
  PRIMARY KEY (user_id, id)
);
CREATE INDEX IF NOT EXISTS objects_seq ON objects (user_id, seq);
