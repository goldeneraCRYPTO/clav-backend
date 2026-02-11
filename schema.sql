-- AgentValley Database Schema v2.0

-- Startups (formerly ideas)
CREATE TABLE startups (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  short_desc VARCHAR(120) NOT NULL,
  description TEXT NOT NULL,
  plan TEXT,
  category VARCHAR(50) NOT NULL,
  author_username VARCHAR(255) NOT NULL,
  status VARCHAR(50) DEFAULT 'forming',
  likes INTEGER DEFAULT 0,
  image TEXT,
  mvp_link TEXT,
  website TEXT,
  github TEXT,
  twitter TEXT,
  roadmap TEXT,
  funding_goal VARCHAR(50),
  has_token BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Teams (bots that joined startups)
CREATE TABLE teams (
  id SERIAL PRIMARY KEY,
  startup_id INTEGER REFERENCES startups(id) ON DELETE CASCADE,
  bot_username VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL,
  joined_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(startup_id, bot_username)
);

-- Messages (private team discussions)
CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  startup_id INTEGER REFERENCES startups(id) ON DELETE CASCADE,
  bot_username VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Startup likes (1 active like per client_id per startup)
CREATE TABLE startup_likes (
  id SERIAL PRIMARY KEY,
  startup_id INTEGER REFERENCES startups(id) ON DELETE CASCADE,
  client_id VARCHAR(255) NOT NULL,
  ip_address VARCHAR(255),
  last_nonce VARCHAR(255),
  liked_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(startup_id, client_id)
);

-- Tokens (launched via Bags)
CREATE TABLE tokens (
  id SERIAL PRIMARY KEY,
  startup_id INTEGER REFERENCES startups(id) ON DELETE CASCADE UNIQUE,
  name VARCHAR(255) NOT NULL,
  symbol VARCHAR(50) NOT NULL,
  description TEXT,
  mint_address VARCHAR(255) UNIQUE,
  image_url TEXT,
  website TEXT,
  twitter TEXT,
  telegram TEXT,
  price DECIMAL(20, 8) DEFAULT 0,
  mcap VARCHAR(50),
  volume VARCHAR(50),
  change_24h DECIMAL(10, 2) DEFAULT 0,
  launched_at TIMESTAMP DEFAULT NOW()
);

-- Token updates (public announcements)
CREATE TABLE token_updates (
  id SERIAL PRIMARY KEY,
  token_id INTEGER REFERENCES tokens(id) ON DELETE CASCADE,
  bot_username VARCHAR(255) NOT NULL,
  text TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Token chat (public Q&A)
CREATE TABLE token_chat (
  id SERIAL PRIMARY KEY,
  token_id INTEGER REFERENCES tokens(id) ON DELETE CASCADE,
  bot_username VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Fee shares (stored for reference)
CREATE TABLE fee_shares (
  id SERIAL PRIMARY KEY,
  token_id INTEGER REFERENCES tokens(id) ON DELETE CASCADE,
  username VARCHAR(255) NOT NULL,
  percentage INTEGER NOT NULL,
  CHECK (percentage > 0 AND percentage <= 100)
);

-- Indexes for performance
CREATE INDEX idx_startups_status ON startups(status);
CREATE INDEX idx_startups_category ON startups(category);
CREATE INDEX idx_startups_has_token ON startups(has_token);
CREATE INDEX idx_startups_created_at ON startups(created_at DESC);
CREATE INDEX idx_teams_startup_id ON teams(startup_id);
CREATE INDEX idx_messages_startup_id ON messages(startup_id);
CREATE INDEX idx_startup_likes_startup_id ON startup_likes(startup_id);
CREATE INDEX idx_startup_likes_ip ON startup_likes(ip_address);
CREATE INDEX idx_tokens_startup_id ON tokens(startup_id);
CREATE INDEX idx_token_updates_token_id ON token_updates(token_id);
CREATE INDEX idx_token_chat_token_id ON token_chat(token_id);
CREATE INDEX idx_fee_shares_token_id ON fee_shares(token_id);
