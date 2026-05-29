{{ config(materialized='view') }}

WITH source AS (
    SELECT * FROM {{ source('raw', 'raw_linux_logs') }}
),

cleaned AS (
    SELECT
        timestamp_raw,
        hostname,
        process,
        pid,
        message,
        log_level,
        is_suspicious,
        source_ip,
        ingested_at,
        log_source,
        CASE
            WHEN message ILIKE '%authentication failure%' THEN 'AUTH_FAILURE'
            WHEN message ILIKE '%check pass%'             THEN 'CHECK_PASS'
            WHEN message ILIKE '%user unknown%'           THEN 'UNKNOWN_USER'
            WHEN message ILIKE '%sudo%'                   THEN 'SUDO_EVENT'
            ELSE 'OTHER'
        END AS attack_type,
        SPLIT_PART(timestamp_raw, ' ', 3) AS time_of_day
    FROM source
)

SELECT * FROM cleaned
