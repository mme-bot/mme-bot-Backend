DROP SCHEMA mmebot CASCADE;
CREATE SCHEMA mmebot;

CREATE EXTENSION vector;

-- =========================================================
-- Core: keys, encryption_contexts
-- =========================================================

CREATE TABLE mmebot.keys (
    key_id       BIGSERIAL PRIMARY KEY,
    alg          VARCHAR(255) NOT NULL,
    valid_from   TIMESTAMPTZ NOT NULL,
    valid_to     TIMESTAMPTZ,
    key_material BYTEA NOT NULL,
    status       VARCHAR(255) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- encryption_contexts
CREATE TABLE mmebot.encryption_contexts (
    encryption_context_id BIGSERIAL PRIMARY KEY,
    iv                    BYTEA NOT NULL,
    tag                   BYTEA NOT NULL,
    aad_hash              BYTEA,
    key_id                BIGINT NOT NULL REFERENCES mmebot.keys (key_id),
    encrypt_at            TIMESTAMPTZ
);

-- =========================================================
-- 1) bot / bot_image
-- =========================================================
CREATE TABLE mmebot.bot (
  bot_id          BIGSERIAL PRIMARY KEY,
  name        VARCHAR(50)    NOT NULL,
  persona     TEXT           NOT NULL,
  script      TEXT,
  is_active   BOOLEAN        NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ    NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ    NOT NULL DEFAULT now(),
  CONSTRAINT uk_bot_name UNIQUE (name)
);

CREATE TABLE mmebot.bot_image (
    bot_image_id BIGSERIAL PRIMARY KEY,
    bot_id       BIGINT NOT NULL,
    mood         VARCHAR(32) NOT NULL,
    url          TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_bot_image_bot FOREIGN KEY (bot_id)
        REFERENCES mmebot.bot (bot_id)    -- 고침: bot(id)
        ON DELETE CASCADE
);

-- =========================================================
-- 2) users
-- =========================================================
CREATE TABLE mmebot.users (
    user_id                 BIGSERIAL PRIMARY KEY,
    bot_id                  BIGINT,
    email                   VARCHAR(320) NOT NULL UNIQUE,
    password                VARCHAR(255) NOT NULL,
    nickname                VARCHAR(40)  NOT NULL,
    is_sns                  BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_context_id   BIGINT NOT NULL,            -- encryption_context_id
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at              TIMESTAMPTZ,
    CONSTRAINT fk_users_bot  FOREIGN KEY (bot_id) REFERENCES mmebot.bot (bot_id),
    CONSTRAINT fk_users_enc  FOREIGN KEY (encryption_context_id)
        REFERENCES mmebot.encryption_contexts (encryption_context_id)
);
CREATE INDEX idx_users_email ON mmebot.users (email);

-- =========================================================
-- 3) sns_users
-- =========================================================
CREATE TABLE mmebot.sns_users (
    sns_user_id             BIGSERIAL PRIMARY KEY,
    users_id                BIGINT NOT NULL,
    provider                VARCHAR(32) NOT NULL,
    provider_uid            VARCHAR(128) NOT NULL,
    encryption_context_id   BIGINT NOT NULL,            -- key_id -> encryption_context_id
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_sns_users_user FOREIGN KEY (users_id)
        REFERENCES mmebot.users (user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_sns_users_enc FOREIGN KEY (encryption_context_id)
        REFERENCES mmebot.encryption_contexts (encryption_context_id)
);

-- =========================================================
-- 4) auth_token
-- =========================================================
CREATE TABLE mmebot.auth_token (
    auth_token_id           BIGSERIAL PRIMARY KEY,
    user_id                 BIGINT NOT NULL,
    type                    VARCHAR(32) NOT NULL,
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expired_at              TIMESTAMPTZ NOT NULL,
    revoked_at              TIMESTAMPTZ,
    user_agent              TEXT,
    ip_address              VARCHAR(255),
    encryption_context_id   BIGINT NOT NULL,            -- key_id -> encryption_context_id
    CONSTRAINT fk_auth_token_user FOREIGN KEY (user_id)
        REFERENCES mmebot.users (user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_auth_token_enc FOREIGN KEY (encryption_context_id)
        REFERENCES mmebot.encryption_contexts (encryption_context_id)
);

CREATE INDEX CONCURRENTLY idx_auth_token_user_issued_desc
ON mmebot.auth_token (user_id, issued_at DESC);

-- =========================================================
-- 5) email_verification
-- =========================================================
CREATE TABLE mmebot.email_verification (
    email_verification_id   BIGSERIAL PRIMARY KEY,
    email                   VARCHAR(320) NOT NULL,
    code                    VARCHAR(16) NOT NULL,
    send_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    expired_at              TIMESTAMPTZ NOT NULL,
    sent_count              INT NOT NULL DEFAULT 0,
    encryption_context_id   BIGINT NOT NULL,            -- key_id -> encryption_context_id
    CONSTRAINT fk_email_verification_enc FOREIGN KEY (encryption_context_id)
        REFERENCES mmebot.encryption_contexts (encryption_context_id)
);
CREATE INDEX idx_email_verification_email_sendat_desc ON mmebot.email_verification (email, send_at DESC);

-- =========================================================
-- 7) diary
-- =========================================================
CREATE TABLE mmebot.diary (
    diary_id                BIGSERIAL PRIMARY KEY,
    user_id                 BIGINT NOT NULL,
    content                 TEXT NOT NULL,
    emotion                 VARCHAR(32) NOT NULL,
    summary_short           TEXT,
    date                    DATE NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at              TIMESTAMPTZ,
    encryption_context_id   BIGINT NOT NULL,
    CONSTRAINT fk_diary_user FOREIGN KEY (user_id)
        REFERENCES mmebot.users (user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_diary_enc FOREIGN KEY (encryption_context_id)
        REFERENCES mmebot.encryption_contexts (encryption_context_id)
);

CREATE INDEX idx_diary_user_date ON mmebot.diary (user_id, date);

-- =========================================================
-- 8) chat_session
-- =========================================================
CREATE TABLE mmebot.chat_session (
    chat_session_id         BIGSERIAL PRIMARY KEY,
    diary_id                BIGINT NOT NULL UNIQUE,
    bot_id                  BIGINT NOT NULL,
    status                  VARCHAR(32) NOT NULL,
    send_count              INT NOT NULL DEFAULT 0,
    summary                 TEXT,
    encryption_context_id   BIGINT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ,
    CONSTRAINT fk_chat_session_diary FOREIGN KEY (diary_id)
        REFERENCES mmebot.diary (diary_id),
    CONSTRAINT fk_chat_session_bot FOREIGN KEY (bot_id)
        REFERENCES mmebot.bot (bot_id),
    CONSTRAINT fk_chat_session_enc FOREIGN KEY (encryption_context_id)
        REFERENCES mmebot.encryption_contexts (encryption_context_id)
);
CREATE UNIQUE INDEX idx_chat_session_diary_id ON mmebot.chat_session (diary_id);

-- =========================================================
-- 9) chat_message
-- =========================================================
CREATE TABLE mmebot.chat_message (
    chat_message_id         BIGSERIAL PRIMARY KEY,
    chat_session_id         BIGINT NOT NULL,
    seq                     INT NOT NULL,
    role                    VARCHAR(16) NOT NULL,
    content                 TEXT NOT NULL,
    encryption_context_id   BIGINT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_chat_message_session FOREIGN KEY (chat_session_id)
        REFERENCES mmebot.chat_session (chat_session_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_chat_message_enc FOREIGN KEY (encryption_context_id)
        REFERENCES mmebot.encryption_contexts (encryption_context_id)
);
CREATE INDEX idx_chat_message_session_seq ON mmebot.chat_message (chat_session_id, seq);

-- =========================================================
-- diary_chunk / embedding
-- =========================================================
-- diary_chunk: (기존과 동일, 단 embedding_id 컬럼 삭제 권장)
CREATE TABLE mmebot.diary_chunk (
  diary_chunk_id           BIGSERIAL PRIMARY KEY,
  diary_id                 BIGINT NOT NULL,
  chunk_index              INT NOT NULL,
  content                  TEXT NOT NULL,
  token_count              INT,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  encryption_context_id    BIGINT NOT NULL,
  CONSTRAINT fk_diary_chunk_diary FOREIGN KEY (diary_id)
    REFERENCES mmebot.diary (diary_id) ON DELETE CASCADE,
  CONSTRAINT fk_diary_chunk_enc FOREIGN KEY (encryption_context_id)
    REFERENCES mmebot.encryption_contexts (encryption_context_id)
);
CREATE UNIQUE INDEX ux_diary_chunk_diary_index
  ON mmebot.diary_chunk(diary_id, chunk_index);

-- 임베딩: 청크를 1:1로 참조 (유일키 + CASCADE)
CREATE TABLE mmebot.diary_chunk_embedding (
  diary_chunk_embedding_id BIGSERIAL PRIMARY KEY,
  diary_chunk_id           BIGINT NOT NULL UNIQUE,
  embedding                vector(1536) NOT NULL,
  CONSTRAINT fk_chunk_embedding FOREIGN KEY (diary_chunk_id)
    REFERENCES mmebot.diary_chunk (diary_chunk_id) ON DELETE CASCADE
);

CREATE TABLE mmebot.roles (
                              role_id BIGSERIAL PRIMARY KEY,              -- role 테이블의 PK
                              user_id BIGINT NOT NULL,               -- users.id 참조
                              role_name VARCHAR(50) NOT NULL,        -- 권한명 (예: ROLE_ADMIN, ROLE_USER)
                              created_at TIMESTAMP DEFAULT NOW(),
                              updated_at TIMESTAMP DEFAULT NOW(),

                              CONSTRAINT fk_user_roles
                                  FOREIGN KEY (user_id)
                                      REFERENCES mmebot.users(user_id)
                                      ON DELETE CASCADE
);

-- 유저별 조회 성능을 위한 인덱스
CREATE INDEX idx_roles_user_id ON mmebot.roles(user_id);