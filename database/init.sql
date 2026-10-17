-- Rusty Hook schema. Runs once on an empty volume (docker-entrypoint-initdb.d).

BEGIN;

-- Hook endpoint and the response it returns to callers.
CREATE TABLE endpoints (
    id                uuid        PRIMARY KEY,
    name              text        NOT NULL DEFAULT ''
                                  CHECK (char_length(name) <= 100),
    resp_status       smallint    NOT NULL DEFAULT 200
                                  CHECK (resp_status BETWEEN 200 AND 599),
    resp_content_type text        NOT NULL DEFAULT 'text/plain; charset=utf-8'
                                  CHECK (octet_length(resp_content_type) BETWEEN 1 AND 200),
    resp_body         text        NOT NULL DEFAULT 'ok'
                                  CHECK (octet_length(resp_body) <= 65536),
    resp_delay_ms     integer     NOT NULL DEFAULT 0
                                  CHECK (resp_delay_ms BETWEEN 0 AND 10000),
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- Captured requests. Headers: jsonb array of [name, value] pairs, order kept.
CREATE TABLE requests (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id  uuid        NOT NULL REFERENCES endpoints (id) ON DELETE CASCADE,
    method       text        NOT NULL CHECK (octet_length(method) <= 32),
    path         text        NOT NULL,
    query        text        NOT NULL DEFAULT '',
    content_type text,
    headers      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    body         bytea       NOT NULL DEFAULT ''::bytea,
    size         integer     GENERATED ALWAYS AS (octet_length(body)) STORED,
    ip           text,
    received_at  timestamptz NOT NULL DEFAULT now()
);

-- Newest-first per endpoint: lists, paging and trimming.
CREATE INDEX requests_endpoint_id_idx ON requests (endpoint_id, id DESC);
-- Retention sweep by age.
CREATE INDEX requests_received_at_idx ON requests (received_at);

-- Panel sessions. Only the SHA-256 of the token is stored.
CREATE TABLE sessions (
    token_hash bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    -- Fingerprint of ADMIN_KEY at login: key rotation invalidates sessions.
    key_fp     bytea       NOT NULL CHECK (octet_length(key_fp) = 8),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

COMMIT;
