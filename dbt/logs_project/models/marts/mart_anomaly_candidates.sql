{{ config(materialized='table') }}

WITH ssh AS (
    SELECT * FROM {{ ref('stg_ssh_logs') }}
),

linux AS (
    SELECT * FROM {{ ref('stg_linux_logs') }}
),

combined AS (
    SELECT * FROM ssh
    UNION ALL
    SELECT * FROM linux
),

aggregated AS (
    SELECT
        source_ip,
        log_source,
        attack_type,
        COUNT(*) AS total_events,
        SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) AS suspicious_events,
        ROUND(
            SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2
        ) AS suspicion_rate,
        CASE
            WHEN COUNT(*) > 100 THEN 'CRITICAL'
            WHEN COUNT(*) > 20  THEN 'HIGH'
            WHEN COUNT(*) > 5   THEN 'MEDIUM'
            ELSE 'LOW'
        END AS risk_level
    FROM combined
    WHERE source_ip IS NOT NULL
    GROUP BY source_ip, log_source, attack_type
)

SELECT * FROM aggregated
ORDER BY suspicious_events DESC
