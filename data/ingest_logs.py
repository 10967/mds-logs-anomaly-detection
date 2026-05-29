import pandas as pd
import re
from sqlalchemy import create_engine, text
from datetime import datetime

# ── Connexion PostgreSQL ──────────────────────────────────────
engine = create_engine(
    "postgresql://mdsuser:mdspassword@localhost:5432/logs_db"
)

# ── Parser SSH_2k.log ─────────────────────────────────────────
def parse_ssh_log(filepath):
    records = []
    # Format : Dec 10 06:55:46 LabSZ sshd[24200]: message
    pattern = r'^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.+)$'

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            m = re.match(pattern, line)
            if m:
                message = m.group(5)
                records.append({
                    'timestamp_raw' : m.group(1),
                    'hostname'      : m.group(2),
                    'process'       : m.group(3),
                    'pid'           : int(m.group(4)),
                    'message'       : message,
                    'log_level'     : classify_level(message),
                    'is_suspicious' : is_suspicious(message),
                    'source_ip'     : extract_ip(message),
                    'ingested_at'   : datetime.now(),
                    'log_source'    : 'SSH'
                })

    return pd.DataFrame(records)


# ── Parser Linux_2k.log ───────────────────────────────────────
def parse_linux_log(filepath):
    records = []
    # Format : Jun 14 15:16:01 combo sshd(pam_unix)[19939]: message
    pattern = r'^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(.+)\[(\d+)\]:\s+(.+)$'

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            m = re.match(pattern, line)
            if m:
                message = m.group(5)
                records.append({
                    'timestamp_raw' : m.group(1),
                    'hostname'      : m.group(2),
                    'process'       : m.group(3),
                    'pid'           : int(m.group(4)),
                    'message'       : message,
                    'log_level'     : classify_level(message),
                    'is_suspicious' : is_suspicious(message),
                    'source_ip'     : extract_ip(message),
                    'ingested_at'   : datetime.now(),
                    'log_source'    : 'Linux'
                })

    return pd.DataFrame(records)


# ── Fonctions utilitaires ─────────────────────────────────────
def classify_level(message):
    msg = message.lower()
    if any(w in msg for w in ['error', 'failed', 'failure', 'invalid', 'break-in']):
        return 'WARNING'
    elif any(w in msg for w in ['accepted', 'opened', 'session']):
        return 'INFO'
    else:
        return 'DEBUG'

def is_suspicious(message):
    msg = message.lower()
    return any(w in msg for w in [
        'failed password', 'invalid user', 'break-in',
        'authentication failure', 'check pass', 'illegal user'
    ])

def extract_ip(message):
    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
    return match.group(1) if match else None


# ── Chargement dans PostgreSQL ────────────────────────────────
def load_to_postgres(df, table_name):
    df.to_sql(
        table_name,
        engine,
        schema='raw',
        if_exists='replace',
        index=False
    )
    print(f"  ✅ {len(df)} lignes chargees dans raw.{table_name}")


# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Ingestion des logs ===")

    base = r"C:\Users\malak\mds-logs-project\data\raw"

    print("\n[1/2] Parsing SSH_2k.log...")
    df_ssh = parse_ssh_log(f"{base}\\SSH_2k.log")
    print(f"  Lignes parsees : {len(df_ssh)}")
    print(f"  Lignes suspectes : {df_ssh['is_suspicious'].sum()}")
    load_to_postgres(df_ssh, "raw_ssh_logs")

    print("\n[2/2] Parsing Linux_2k.log...")
    df_linux = parse_linux_log(f"{base}\\Linux_2k.log")
    print(f"  Lignes parsees : {len(df_linux)}")
    print(f"  Lignes suspectes : {df_linux['is_suspicious'].sum()}")
    load_to_postgres(df_linux, "raw_linux_logs")

    print("\n=== Verification finale ===")
    with engine.connect() as conn:
        for table in ["raw_ssh_logs", "raw_linux_logs"]:
            count = conn.execute(
                text(f"SELECT COUNT(*) FROM raw.{table}")
            ).scalar()
            print(f"  ✅ raw.{table} : {count} lignes dans PostgreSQL")

    print("\n=== Ingestion terminee ===")