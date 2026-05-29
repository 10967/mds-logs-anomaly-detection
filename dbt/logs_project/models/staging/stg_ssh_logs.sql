{{ config(materialized='view') }}

WITH source AS (
    SELECT * FROM {{ source('raw', 'raw_ssh_logs') }}
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
            WHEN message ILIKE '%Invalid user%'           THEN 'INVALID_USER'
            WHEN message ILIKE '%Failed password%'        THEN 'FAILED_PASSWORD'
            WHEN message ILIKE '%BREAK-IN ATTEMPT%'       THEN 'BREAK_IN'
            WHEN message ILIKE '%authentication failure%' THEN 'AUTH_FAILURE'
            WHEN message ILIKE '%Accepted password%'      THEN 'ACCEPTED'
            ELSE 'OTHER'
        END AS attack_type,
        SPLIT_PART(timestamp_raw, ' ', 3) AS time_of_day
    FROM source
)

SELECT * FROM cleaned
