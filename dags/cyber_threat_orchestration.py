from datetime import datetime, timedelta
import os
import subprocess

from airflow.sdk import DAG, task
from airflow.providers.standard.operators.python import ShortCircuitOperator

from abuse_change_control import detect_abuse_changes, commit_abuse_state

PROJECT_DIR = "/opt/airflow/project"


def run_script(script_name: str):
    process = subprocess.Popen(
        ["python", script_name],
        cwd=PROJECT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=os.environ.copy(),
        bufsize=1,
    )

    for line in process.stdout:
        print(line, end="")

    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"{script_name} failed with exit code {return_code}")


with DAG(
    dag_id="cyber_threat_orchestration",
    start_date=datetime(2026, 4, 25),
    schedule="@daily",
    catchup=False,
    max_active_runs=1,
    tags=["cyber", "minio", "kafka", "airflow"],
) as dag:

    @task
    def ingest_abuseipdb():
        run_script("ingest_abuseipdb_MinIO.py")

    @task
    def transform_abuseipdb():
        run_script("transform_abuseipdb_MinIO.py")

    @task
    def ingest_geoip():
        run_script("ingest_geoip_MinIO.py")

    @task
    def transform_geoip():
        run_script("transform_geoip_MinIO.py")

    @task
    def ingest_otx():
        run_script("ingest_otx_MinIO.py")

    @task
    def transform_otx():
        run_script("transform_otx_MinIO.py")

    @task
    def producer_abuseipdb_to_kafka():
        run_script("producer_abuseipdb_MinIO_Kafka.py")

    @task
    def commit_abuse_state_task():
        commit_abuse_state()

    t1 = ingest_abuseipdb()

    t_check_changes = ShortCircuitOperator(
        task_id="check_abuse_changes",
        python_callable=detect_abuse_changes,
    )

    t2 = transform_abuseipdb()
    t3 = ingest_geoip()
    t4 = transform_geoip()
    t5 = ingest_otx()
    t6 = transform_otx()
    t7 = producer_abuseipdb_to_kafka()
    t8 = commit_abuse_state_task()

    t1 >> t_check_changes
    t_check_changes >> [t2, t3, t5]

    t3 >> t4
    t5 >> t6

    [t2, t4, t6] >> t7 >> t8