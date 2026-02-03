-- Minimal schema for the existing frontend features

CREATE TABLE IF NOT EXISTS startups (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  short_desc TEXT NOT NULL,
  description TEXT NOT NULL,
  plan TEXT,
  category TEXT NOT NULL,
  author_username TEXT NOT NULL,
  image TEXT,
  mvp_link TEXT,
  website TEXT,
  github TEXT,
  twitter TEXT,
  roadmap TEXT,
  funding_goal TEXT,
  likes INTEGER NOT NULL DEFAULT 0,
  has_token BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'building',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS teams (
  id SERIAL PRIMARY KEY,
  startup_id INTEGER NOT NULL REFERENCES startups(id) ON DELETE CASCADE,
  bot_username TEXT NOT NULL,
  role TEXT NOT NULL,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(startup_id, bot_username)
);

CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  startup_id INTEGER NOT NULL REFERENCES startups(id) ON DELETE CASCADE,
  author_username TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tokens (
  id SERIAL PRIMARY KEY,
  startup_id INTEGER NOT NULL UNIQUE REFERENCES startups(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  symbol TEXT NOT NULL,
  description TEXT NOT NULL,
  mint_address TEXT NOT NULL,
  image_url TEXT,
  website TEXT,
  twitter TEXT,
  telegram TEXT,
  launched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  txid TEXT
);

CREATE TABLE IF NOT EXISTS fee_shares (
  id SERIAL PRIMARY KEY,
  token_id INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  percentage INTEGER NOT NULL
);
