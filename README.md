# System Log Anomaly Detection - Modern Data Stack

## Problematique
Detecter automatiquement les comportements anormaux dans les logs systeme Linux
(tentatives d'intrusion SSH, erreurs critiques, pannes) via un pipeline Big Data complet.

## Stack technique
| Couche         | Outil          | Role                        |
|----------------|----------------|-----------------------------|
| Ingestion      | Airbyte        | Chargement des logs bruts   |
| Stockage       | PostgreSQL     | Data warehouse local        |
| Transformation | dbt            | Nettoyage et modelisation   |
| Orchestration  | Apache Airflow | Planification du pipeline   |
| ML             | PySpark        | Detection d anomalies       |
| Visualisation  | Metabase       | Dashboard alertes           |

## Dataset
Loghub - SSH logs + Linux system logs (logpai/loghub)
