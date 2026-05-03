-- ============================================================
-- Financial Data Normalizer — Supabase Schema Migration
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

-- API Keys table
-- Stores hashed keys with email, Stripe customer linkage, and activity tracking.
CREATE TABLE IF NOT EXISTS api_keys (
    id                  BIGSERIAL PRIMARY KEY,
    key_prefix          TEXT        NOT NULL,
    key_hash            TEXT        NOT NULL UNIQUE,
    label               TEXT        NOT NULL DEFAULT '',
    email               TEXT        NOT NULL DEFAULT '',
    stripe_customer_id  TEXT        NOT NULL DEFAULT '',
    is_active           BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_email  ON api_keys(email);

-- Usage Events table
-- Per-request audit log: tracks matched/fallback/unmatched counts
-- for the data flywheel and billing reconciliation.
CREATE TABLE IF NOT EXISTS usage_events (
    id                  BIGSERIAL PRIMARY KEY,
    api_key_id          BIGINT      NOT NULL REFERENCES api_keys(id),
    endpoint            TEXT        NOT NULL,
    transaction_count   INTEGER     NOT NULL DEFAULT 0,
    matched_count       INTEGER     NOT NULL DEFAULT 0,
    fallback_count      INTEGER     NOT NULL DEFAULT 0,
    unmatched_count     INTEGER     NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_usage_events_key ON usage_events(api_key_id);
CREATE INDEX IF NOT EXISTS idx_usage_events_ts  ON usage_events(created_at);

-- ============================================================
-- Row Level Security (RLS)
-- Service role key bypasses RLS, so these tables are accessible
-- only from the server side. Enable RLS to block anon/public access.
-- ============================================================

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;

-- No RLS policies = anon key has zero access.
-- The service_role key (used by the API) bypasses RLS entirely.
