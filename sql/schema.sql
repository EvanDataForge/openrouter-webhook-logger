-- OpenRouter Webhook Logger: Database Schema
-- Import with: mysql -u USER -p DATABASE < schema.sql

DROP TABLE IF EXISTS traces;
DROP TABLE IF EXISTS auth_failures;

CREATE TABLE IF NOT EXISTS traces (
    id                      BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    -- Identifiers
    trace_id                VARCHAR(64)     NOT NULL,
    span_id                 VARCHAR(64)     NOT NULL,
    openrouter_trace_id     VARCHAR(128)    DEFAULT NULL,

    -- Model & provider
    request_model           VARCHAR(100)    DEFAULT NULL,
    response_model          VARCHAR(100)    DEFAULT NULL,
    provider_name           VARCHAR(100)    DEFAULT NULL,
    provider_slug           VARCHAR(100)    DEFAULT NULL,

    -- Operation metadata
    operation_name          VARCHAR(50)     DEFAULT NULL,
    span_type               VARCHAR(50)     DEFAULT NULL,
    finish_reason           VARCHAR(50)     DEFAULT NULL,
    finish_reasons          VARCHAR(255)    DEFAULT NULL,
    trace_name              VARCHAR(255)    DEFAULT NULL,

    -- Tokens
    input_tokens            INT UNSIGNED    DEFAULT NULL,
    output_tokens           INT UNSIGNED    DEFAULT NULL,
    total_tokens            INT UNSIGNED    AS (input_tokens + output_tokens) STORED,
    cached_tokens           INT UNSIGNED    DEFAULT NULL,
    reasoning_tokens        INT UNSIGNED    DEFAULT NULL,
    audio_tokens            INT UNSIGNED    DEFAULT NULL,
    video_tokens            INT UNSIGNED    DEFAULT NULL,
    image_tokens            INT UNSIGNED    DEFAULT NULL,

    -- Cost (USD)
    input_cost_usd          DECIMAL(12,8)   DEFAULT NULL,
    output_cost_usd         DECIMAL(12,8)   DEFAULT NULL,
    total_cost_usd          DECIMAL(12,8)   DEFAULT NULL,
    input_unit_price        DECIMAL(16,12)  DEFAULT NULL,
    output_unit_price       DECIMAL(16,12)  DEFAULT NULL,

    -- Timing
    started_at              DATETIME(3)     DEFAULT NULL,
    ended_at                DATETIME(3)     DEFAULT NULL,
    duration_ms             INT UNSIGNED    DEFAULT NULL,

    -- Input / Output content
    span_input              MEDIUMTEXT      DEFAULT NULL,
    span_output             MEDIUMTEXT      DEFAULT NULL,
    trace_input             MEDIUMTEXT      DEFAULT NULL,
    trace_output            MEDIUMTEXT      DEFAULT NULL,
    gen_ai_prompt           MEDIUMTEXT      DEFAULT NULL,
    gen_ai_completion       MEDIUMTEXT      DEFAULT NULL,

    -- Context
    api_key_name            VARCHAR(100)    DEFAULT NULL,
    user_id                 VARCHAR(255)    DEFAULT NULL,
    entity_id               VARCHAR(255)    DEFAULT NULL,

    -- Raw payload (optional, see log_raw_payload in config)
    raw_payload             MEDIUMTEXT      DEFAULT NULL,
    received_at             DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY dedup (trace_id, span_id),
    INDEX idx_request_model  (request_model),
    INDEX idx_response_model (response_model),
    INDEX idx_provider       (provider_slug),
    INDEX idx_received       (received_at),
    INDEX idx_user           (user_id),
    INDEX idx_api_key        (api_key_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_failures (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip          VARCHAR(45)  NOT NULL,
    header_used VARCHAR(64)  DEFAULT NULL,
    failed_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip   (ip),
    INDEX idx_time (failed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
