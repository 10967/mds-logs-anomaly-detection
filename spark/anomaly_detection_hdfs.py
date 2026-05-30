from pyspark.sql import SparkSession
from pyspark.sql.functions import col, when
from pyspark.ml.feature import VectorAssembler, StandardScaler
from pyspark.ml.clustering import KMeans
from pyspark.sql.types import StringType
from pyspark.sql.functions import udf

print("=== Spark ML Pipeline - HDFS Labels Corriges ===")

spark = SparkSession.builder \
    .appName("HDFS_AnomalyDetection_v3") \
    .config("spark.jars.packages", "org.postgresql:postgresql:42.6.0") \
    .config("spark.driver.memory", "3g") \
    .config("spark.executor.memory", "2g") \
    .config("spark.sql.shuffle.partitions", "10") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

DB_URL = "jdbc:postgresql://mds-postgres:5432/logs_db"
DB_PROPS = {
    "user": "mdsuser",
    "password": "mdspassword",
    "driver": "org.postgresql.Driver"
}

print("[1/5] Chargement agregation...")
query = """(
    SELECT
        block_id,
        COUNT(*) AS total_events,
        MAX(CASE WHEN is_anomaly = true THEN 1 ELSE 0 END) AS is_truly_anomaly,
        SUM(CASE WHEN is_anomaly = true THEN 1 ELSE 0 END) AS anomaly_events,
        SUM(CASE WHEN log_level = 'ERROR' THEN 1 ELSE 0 END) AS error_events,
        ROUND(
            SUM(CASE WHEN is_anomaly = true THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2
        ) AS anomaly_rate
    FROM raw.raw_hdfs_logs
    WHERE block_id IS NOT NULL
    GROUP BY block_id
) AS hdfs_agg"""

df = spark.read.jdbc(url=DB_URL, table=query, properties=DB_PROPS)
print(f"  Blocs uniques : {df.count():,}")

print("[2/5] Feature engineering - priorite anomaly_rate...")
df_clean = df.na.fill(0)
assembler = VectorAssembler(
    inputCols=["anomaly_rate", "anomaly_events", "total_events"],
    outputCol="features"
)
df_vec = assembler.transform(df_clean)

print("[3/5] Normalisation...")
scaler = StandardScaler(
    inputCol="features",
    outputCol="scaled_features",
    withMean=True,
    withStd=True
)
df_scaled = scaler.fit(df_vec).transform(df_vec)

print("[4/5] K-Means k=3 - trie par anomaly_rate...")
kmeans = KMeans(featuresCol="scaled_features", k=3, seed=42, maxIter=20)
model = kmeans.fit(df_scaled)
df_pred = model.transform(df_scaled)

centers = model.clusterCenters()
sorted_centers = sorted(enumerate(centers), key=lambda x: x[1][0])
cluster_to_label = {}
labels = ["NORMAL", "SUSPECT", "CRITIQUE"]
for rank, (idx, _) in enumerate(sorted_centers):
    cluster_to_label[idx] = labels[rank]
print(f"  Mapping : {cluster_to_label}")

label_udf = udf(lambda c: cluster_to_label.get(c, "UNKNOWN"), StringType())
df_result = df_pred.withColumn("anomaly_label", label_udf(col("prediction")))

print("[5/5] Sauvegarde...")
df_final = df_result.select(
    "block_id", "total_events", "anomaly_events",
    "error_events", "anomaly_rate", "is_truly_anomaly",
    "anomaly_label", col("prediction").alias("cluster_id")
)

df_final.write.jdbc(
    url=DB_URL,
    table="ml.ml_hdfs_results",
    mode="overwrite",
    properties=DB_PROPS
)

print("\n=== Resultats ML HDFS ===")
df_final.groupBy("anomaly_label").count().orderBy("anomaly_label").show()

print("=== Validation vs ground truth ===")
df_eval = df_final.withColumn(
    "correct",
    when((col("anomaly_label") == "CRITIQUE") & (col("is_truly_anomaly") == 1), 1)
    .when((col("anomaly_label") == "NORMAL") & (col("is_truly_anomaly") == 0), 1)
    .otherwise(0)
)
correct = df_eval.filter(col("correct") == 1).count()
total = df_eval.count()
print(f"  Precision : {round(correct*100.0/total, 2)}%")

print("\n=== Top 10 blocs CRITIQUE ===")
df_final.filter(col("anomaly_label") == "CRITIQUE") \
    .orderBy(col("anomaly_rate").desc(), col("anomaly_events").desc()) \
    .select("block_id", "total_events", "anomaly_events", "anomaly_rate") \
    .show(10, truncate=False)

print("=== Pipeline ML HDFS termine ===")
spark.stop()
