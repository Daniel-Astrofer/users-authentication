ALTER TABLE IF EXISTS public.notifications ADD COLUMN IF NOT EXISTS metadata_json TEXT;

CREATE TABLE public.financial_notification_inbox (
    event_id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL CHECK (user_id > 0),
    transaction_id UUID NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.financial_notification_stream (
    user_id BIGINT NOT NULL CHECK (user_id > 0),
    transaction_id UUID NOT NULL,
    last_sequence BIGINT NOT NULL CHECK (last_sequence >= 0),
    last_occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, transaction_id)
);
