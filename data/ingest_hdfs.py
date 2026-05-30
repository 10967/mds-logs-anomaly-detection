import pandas as pd
import re
from sqlalchemy import create_engine, text
from datetime import datetime

engine = create_engine(
    'postgresql://mdsuser:mdspassword@localhost:5432/logs_db'
)

def parse_hdfs_log(filepath, anomaly_filepath, chunksize=100000):
    print(f"  Chargement anomaly labels...")
    anomaly_df = pd.read_csv(anomaly_filepath)
    print(f"  Labels charges : {len(anomaly_df)} blocs")
    print(f"  Colonnes : {list(anomaly_df.columns)}")

    anomaly_map = {}
    if 'BlockId' in anomaly_df.columns and 'Label' in anomaly_df.columns:
        anomaly_map = dict(zip(anomaly_df['BlockId'].astype(str), anomaly_df['Label']))
    elif 'block_id' in anomaly_df.columns and 'label' in anomaly_df.columns:
        anomaly_map = dict(zip(anomaly_df['block_id'].astype(str), anomaly_df['label']))

    print(f"  Anomalies connues : {sum(1 for v in anomaly_map.values() if v == 'Anomaly')}")

    pattern = r'^(\d{6})\s(\d{6})\s(\d+)\s(\w+)\s([\w\.\$]+):\s(.+)$'
    block_pattern = r'(blk_-?\d+)'
    ip_pattern = r'/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

    chunk_records = []
    total_lines = 0
    total_inserted = 0
    chunk_num = 0

    print(f"  Parsing en cours (chunks de {chunksize} lignes)...")

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            m = re.match(pattern, line)
            if m:
                date_raw = m.group(1)
                time_raw = m.group(2)
                thread = m.group(3)
                level = m.group(4)
                component = m.group(5)
                message = m.group(6)

                block_match = re.search(block_pattern, message)
                block_id = block_match.group(1) if block_match else None

                ip_match = re.search(ip_pattern, message)
                source_ip = ip_match.group(1) if ip_match else None

                true_label = anomaly_map.get(str(block_id), 'Normal') if block_id else 'Normal'
                is_anomaly = true_label == 'Anomaly'

                chunk_records.append({
                    'date_raw'   : date_raw,
                    'time_raw'   : time_raw,
                    'thread'     : thread,
                    'log_level'  : level,
                    'component'  : component,
                    'message'    : message,
                    'block_id'   : block_id,
                    'source_ip'  : source_ip,
                    'true_label' : true_label,
                    'is_anomaly' : is_anomaly,
                    'log_source' : 'HDFS',
                    'ingested_at': datetime.now()
                })

            if len(chunk_records) >= chunksize:
                chunk_num += 1
                df_chunk = pd.DataFrame(chunk_records)
                mode = 'replace' if chunk_num == 1 else 'append'
                df_chunk.to_sql('raw_hdfs_logs', engine, schema='raw',
                               if_exists=mode, index=False)
                total_inserted += len(df_chunk)
                print(f"  Chunk {chunk_num} insere : {total_inserted:,} lignes total")
                chunk_records = []

    if chunk_records:
        chunk_num += 1
        df_chunk = pd.DataFrame(chunk_records)
        mode = 'replace' if chunk_num == 1 else 'append'
        df_chunk.to_sql('raw_hdfs_logs', engine, schema='raw',
                       if_exists=mode, index=False)
        total_inserted += len(df_chunk)

    print(f"\n  Total lignes parsees  : {total_lines:,}")
    print(f"  Total lignes inserees : {total_inserted:,}")
    return total_inserted

if __name__ == '__main__':
    print("=== Ingestion HDFS.log (11M lignes) ===")

    base = r'C:\Users\malak\mds-logs-project\data\raw'
    total = parse_hdfs_log(
        filepath=f'{base}\\HDFS.log',
        anomaly_filepath=f'{base}\\anomaly_label.csv',
        chunksize=100000
    )

    print('\n=== Verification finale ===')
    with engine.connect() as conn:
        count = conn.execute(text('SELECT COUNT(*) FROM raw.raw_hdfs_logs')).scalar()
        anomalies = conn.execute(text('SELECT COUNT(*) FROM raw.raw_hdfs_logs WHERE is_anomaly = true')).scalar()
        print(f'  Total lignes : {count:,}')
        print(f'  Vraies anomalies : {anomalies:,}')

    print('=== Ingestion HDFS terminee ===')
