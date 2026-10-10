-- NOTE (2026-10-10): this file was the plan. The built schema is in
-- neurawall/services/control_plane/migrations/versions/0004..0007 and db.py; where they differ,
-- replica/build-log.md lists why (secret_nonce instead of secret_hash, no subscriptions check,
-- llm_usage without alert_id, delivery status pending|sent|dead, 62-day usage retention).
-- NeuraWall: schema delta for the NEXORA Core integration ("linked mode").
-- Postgres flavour. The real migrations are Alembic 0004-0006 and must also run on SQLite
-- (the single-host default), so they use the existing conventions: integer ids,
-- epoch seconds as float (UTC), JSON columns, String(n) enums with a check constraint.
-- Not repeated here: the 12 existing tables (see neurawall/services/control_plane/db.py).
--
-- Access rules: no row level security. A control plane serves exactly one organisation, so
-- there is no tenant column to filter on. Every route authorises with
-- neurawall.security.rbac.authorize(role, Permission) before touching data.

-- ---------------------------------------------------------------- 0004_nexora_link

-- Users stay local (roles, four-eyes, deactivation live in NeuraWall) but become a projection
-- of the NEXORA identity when they arrive through SSO.
alter table users
    add column external_id   varchar(64) null,                 -- Clerk user id ("user_..."), stable across email changes
    add column auth_provider varchar(12) not null default 'local'
        check (auth_provider in ('local', 'nexora'));
create unique index users_external_id_key on users (external_id) where external_id is not null;

-- A paid plan pushed from NEXORA is stored as a normal subscription row so
-- active_subscription(), the 3-day grace and plan() keep working unchanged.
--   provider                  = 'nexora'
--   provider_subscription_id  = 'nexora:<org_id>:neurawall'   (unique, so a sync is an upsert)
--   provider_customer_id      = null
-- No column change; one check so nothing else can write to it by accident.
alter table subscriptions
    add constraint subscriptions_provider_chk check (provider in ('stripe', 'nexora'));

-- Durable outbox for events to NEXORA (C-EVENT). Written in the same transaction as the
-- change that caused the event; a background flusher sends and marks sent_at.
create table core_outbox (
    id          integer primary key generated always as identity,
    event_id    varchar(36)      not null unique,              -- uuid4, used as the idempotency key
    event_type  varchar(60)      not null,                     -- e.g. neurawall.alert.created
    payload     jsonb            not null,                     -- counts and ids only, never IPs, emails or flow data
    created_at  double precision not null,
    sent_at     double precision null,
    attempts    integer          not null default 0,
    next_try_at double precision not null,
    last_error  varchar(200)     null
);
create index core_outbox_pending_idx on core_outbox (next_try_at) where sent_at is null;
create index core_outbox_sent_idx    on core_outbox (sent_at)     where sent_at is not null;  -- purge job

-- The last pull from NEXORA is kept in `settings` (key 'nexora.sync'): {last_ok, last_try,
-- plan_id, status, error}. No table needed.

-- ---------------------------------------------------------------- 0005_llm_usage

-- One row per Tier 3 call that reached the model (heuristic answers are not rows).
-- Source of truth for the monthly budget on Business and Enterprise.
create table llm_usage (
    id            integer primary key generated always as identity,
    ts            double precision not null,
    kind          varchar(12)      not null
        check (kind in ('triage', 'draft', 'narrate', 'explain')),
    model         varchar(60)      not null,
    input_tokens  integer          not null default 0 check (input_tokens  >= 0),
    output_tokens integer          not null default 0 check (output_tokens >= 0),
    alert_id      integer          null references alerts(id) on delete set null,
    outcome       varchar(8)       not null default 'ok'
        check (outcome in ('ok', 'refused', 'error', 'timeout'))
);
create index llm_usage_ts_idx on llm_usage (ts);                 -- budget = count(*) where ts >= period_start
-- Retention follows flow retention (purged by the existing maintenance loop).

-- ---------------------------------------------------------------- 0006_notifications

create table notification_channels (
    id          integer primary key generated always as identity,
    name        varchar(80)      not null unique,
    kind        varchar(12)      not null default 'webhook'
        check (kind in ('webhook')),                              -- Slack/Teams/PagerDuty/SIEM via generic JSON
    url         varchar(500)     not null,                        -- https only; SSRF-checked on save and on every send
    secret_hash varchar(64)      not null,                        -- not the secret: see note below
    events      jsonb            not null default '[]',           -- e.g. ["alert.high","draft.pending","node.stale"]
    min_severity varchar(10)     not null default 'high'
        check (min_severity in ('low', 'medium', 'high', 'critical')),
    active      boolean          not null default true,
    created_by  varchar(254)     not null,
    created_at  double precision not null
);
-- The signing secret is shown once and the HMAC key is stored encrypted with the same
-- mechanism as other server-side secrets (see architecture.md, "Secrets"); `secret_hash`
-- only lets the console say "secret set" and detect rotation.

create table notification_deliveries (
    id          integer primary key generated always as identity,
    channel_id  integer          not null references notification_channels(id) on delete cascade,
    event_type  varchar(40)      not null,
    ref         varchar(64)      not null,                        -- alert id / draft id
    status      varchar(8)       not null default 'pending'
        check (status in ('pending', 'sent', 'failed', 'dead')),
    attempts    integer          not null default 0,
    next_try_at double precision not null,
    http_status integer          null,
    created_at  double precision not null,
    sent_at     double precision null,
    unique (channel_id, event_type, ref)                          -- one notification per event per channel
);
create index notification_deliveries_pending_idx on notification_deliveries (next_try_at) where status = 'pending';
