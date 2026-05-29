from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from datetime import datetime, timedelta
import pandas as pd
import re
from sqlalchemy import create_engine, text

default_args = {
    'owner': 'mds-project',
    'retries': 1,
    'retry_delay': timedelta(minutes=2),
}

def ingest_logs():
    engine = create_engine(
        'postgresql://mdsuser:mdspassword@host.docker.internal:5432/logs_db'
    )

    def classify_level(message):
        msg = message.lower()
        if any(w in msg for w in ['error','failed','failure','invalid','break-in']):
            return 'WARNING'
        elif any(w in msg for w in ['accepted','opened','session']):
            return 'INFO'
        return 'DEBUG'

    def is_suspicious(message):
        msg = message.lower()
        return any(w in msg for w in [
            'failed password','invalid user','break-in',
            'authentication failure','check pass','illegal user'
        ])

    def extract_ip(message):
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
        return match.group(1) if match else None

    records = []
    pattern = r'^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.+)$'
    filepath = '/opt/airflow/data/raw/SSH_2k.log'

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            m = re.match(pattern, line)
            if m:
                message = m.group(5)
                records.append({
                    'timestamp_raw': m.group(1),
                    'hostname': m.group(2),
                    'process': m.group(3),
                    'pid': int(m.group(4)),
                    'message': message,
                    'log_level': classify_level(message),
                    'is_suspicious': is_suspicious(message),
                    'source_ip': extract_ip(message),
                    'log_source': 'SSH'
                })

    df = pd.DataFrame(records)

    with engine.connect() as conn:
        conn.execute(text('TRUNCATE TABLE raw.raw_ssh_logs'))

    df.to_sql('raw_ssh_logs', engine, schema='raw', if_exists='append', index=False)
    print(f'Ingestion OK : {len(df)} lignes')

with DAG(
    dag_id='logs_anomaly_detection_pipeline',
    default_args=default_args,
    description='Pipeline complet detection anomalies logs',
    schedule_interval='@daily',
    start_date=datetime(2024, 1, 1),
    catchup=False,
    tags=['security', 'logs', 'anomaly'],
) as dag:

    t1_ingest = PythonOperator(
        task_id='ingest_ssh_logs',
        python_callable=ingest_logs,
    )

    t2_transform = BashOperator(
        task_id='dbt_transform',
        bash_command='echo "dbt transform - a configurer"',
    )

    t3_check = BashOperator(
        task_id='check_anomalies',
        bash_command='echo "Pipeline termine avec succes"',
    )

    t1_ingest >> t2_transform >> t3_check
