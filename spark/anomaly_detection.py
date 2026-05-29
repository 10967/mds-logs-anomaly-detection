from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from pyspark.ml.feature import VectorAssembler, StandardScaler
from pyspark.ml.clustering import KMeans
from pyspark.sql.types import StringType
from pyspark.sql.functions import udf

print("=== Demarrage Spark ML Pipeline ===")

spark = SparkSession.builder \
    .appName("LogAnomalyDetection") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

DB_URL = "jdbc:postgresql://mds-postgres:5432/logs_db"
DB_PROPS = {
    "user": "mdsuser",
    "password": "mdspassword",
    "driver": "org.postgresql.Driver"
}

print("[1/5] Chargement des donnees depuis PostgreSQL...")
df = spark.read.jdbc(
    url=DB_URL,
    table="staging_marts.mart_anomaly_candidates",
    properties=DB_PROPS
)
print(f"  Lignes chargees : {df.count()}")

print("[2/5] Feature engineering...")
df_features = df.select(
    col("source_ip"),
    col("log_source"),
    col("attack_type"),
    col("total_events").cast("double"),
    col("suspicious_events").cast("double"),
    col("suspicion_rate").cast("double"),
    col("risk_level")
).na.fill(0)

assembler = VectorAssembler(
    inputCols=["total_events", "suspicious_events", "suspicion_rate"],
    outputCol="features"
)
df_vec = assembler.transform(df_features)

print("[3/5] Normalisation...")
scaler = StandardScaler(
    inputCol="features",
    outputCol="scaled_features",
    withMean=True,
    withStd=True
)
df_scaled = scaler.fit(df_vec).transform(df_vec)

print("[4/5] K-Means clustering k=3...")
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

print("[5/5] Sauvegarde dans ml.ml_anomaly_results...")
df_final = df_result.select(
    "source_ip", "log_source", "attack_type",
    "total_events", "suspicious_events", "suspicion_rate",
    "risk_level", "anomaly_label",
    col("prediction").alias("cluster_id")
)

df_final.write.jdbc(
    url=DB_URL,
    table="ml.ml_anomaly_results",
    mode="overwrite",
    properties=DB_PROPS
)

print("=== Resultats ML ===")
df_final.groupBy("anomaly_label").count().orderBy("anomaly_label").show()
df_final.filter(col("anomaly_label") == "CRITIQUE").show(10, truncate=False)
print("=== Pipeline ML termine ===")
spark.stop()
