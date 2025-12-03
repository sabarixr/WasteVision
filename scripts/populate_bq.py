#!/usr/bin/env python3
"""
scripts/populate_bq.py

Generate synthetic prediction rows and insert into BigQuery.
- Creates table if missing (matching expected schema)
- Inserts in batches using insert_rows_json
- Supports --dry-run to write NDJSON for manual upload with `bq load`

Usage examples:
  # quick dry-run to write 1000 rows to ./out.ndjson
  python3 scripts/populate_bq.py --rows 1000 --dry-run

  # insert 10000 rows into BigQuery (ensure GOOGLE_APPLICATION_CREDENTIALS is set)
  python3 scripts/populate_bq.py --rows 10000 --project your-project --dataset your_dataset --table predictions

Environment variables (optional):
  BQ_PROJECT_ID, BQ_DATASET, BQ_TABLE

Dependencies: google-cloud-bigquery
"""

import os
import sys
import json
import uuid
import random
import argparse
from datetime import datetime, timezone, timedelta

try:
    from google.cloud import bigquery
    from google.api_core.exceptions import NotFound
except Exception:
    bigquery = None


SCHEMA = [
    ("report_id", "INT64"),
    ("filename", "STRING"),
    ("lat", "FLOAT"),
    ("lon", "FLOAT"),
    ("waste_label", "STRING"),
    ("waste_index", "INT64"),
    ("waste_score", "FLOAT"),
    ("urgency_label", "STRING"),
    ("urgency_index", "INT64"),
    ("urgency_score", "FLOAT"),
    ("created_at", "TIMESTAMP"),
]

WASTE_LABELS = ["plastic", "organic", "metal", "glass", "paper", "mixed"]
URGENCY_LABELS = ["immediate", "somewhat_late", "no_need"]


def gen_row(i: int, start_date: datetime = None, end_date: datetime = None):
    """Generate a synthetic row with timestamp spread across a date range."""
    report_id = i + 1
    filename = f"uploads/{uuid.uuid4().hex}_img.jpg"
    lat = round(random.uniform(-37.0, 37.0), 6)
    lon = round(random.uniform(-122.0, 122.0), 6)
    waste_label = random.choice(WASTE_LABELS)
    waste_index = random.randint(0, 10)
    waste_score = round(random.random(), 6)
    urgency_label = random.choices(URGENCY_LABELS, weights=[0.2, 0.2, 0.6])[0]
    urgency_index = {"immediate": 0, "somewhat_late": 1, "no_need": 2}[urgency_label]
    urgency_score = round(random.random(), 6)
    
    # Generate timestamp spread across the date range
    if start_date and end_date:
        delta = end_date - start_date
        random_seconds = random.randint(0, int(delta.total_seconds()))
        created_at = start_date + timedelta(seconds=random_seconds)
    else:
        created_at = datetime.now(timezone.utc)
    
    created_at = created_at.isoformat()

    return {
        "report_id": report_id,
        "filename": filename,
        "lat": lat,
        "lon": lon,
        "waste_label": waste_label,
        "waste_index": waste_index,
        "waste_score": waste_score,
        "urgency_label": urgency_label,
        "urgency_index": urgency_index,
        "urgency_score": urgency_score,
        "created_at": created_at,
    }


def ensure_table(client: "bigquery.Client", dataset_id: str, table_id: str):
    dataset_ref = f"{client.project}.{dataset_id}"
    table_ref = f"{client.project}.{dataset_id}.{table_id}"

    try:
        # create dataset if not exists
        client.get_dataset(dataset_ref)
    except NotFound:
        print(f"Dataset {dataset_ref} not found, creating...")
        ds = bigquery.Dataset(dataset_ref)
        ds.location = "US"
        client.create_dataset(ds)
        print("Dataset created")

    try:
        client.get_table(table_ref)
        print(f"Table {table_ref} exists")
    except NotFound:
        print(f"Table {table_ref} not found, creating with schema...")
        schema = [bigquery.SchemaField(name, t) for name, t in SCHEMA]
        table = bigquery.Table(table_ref, schema=schema)
        table = client.create_table(table)
        print(f"Created table {table.full_table_id}")


def insert_in_batches(client: "bigquery.Client", dataset: str, table: str, rows: list, batch_size: int = 1000):
    table_ref = f"{client.project}.{dataset}.{table}"
    total = len(rows)
    i = 0
    while i < total:
        batch = rows[i:i + batch_size]
        errors = client.insert_rows_json(table_ref, batch)
        if errors:
            print(f"Insert errors at batch starting {i}: {errors}")
            return False
        i += batch_size
        print(f"Inserted {min(i, total)}/{total}")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=1000, help="Number of synthetic rows to generate")
    parser.add_argument("--project", type=str, default=os.environ.get("BQ_PROJECT_ID"), help="GCP project id")
    parser.add_argument("--dataset", type=str, default=os.environ.get("BQ_DATASET"), help="BigQuery dataset")
    parser.add_argument("--table", type=str, default=os.environ.get("BQ_TABLE", "predictions"), help="BigQuery table name")
    parser.add_argument("--batch-size", type=int, default=1000, help="Insert batch size")
    parser.add_argument("--dry-run", action="store_true", help="Write NDJSON to ./out.ndjson instead of inserting")
    parser.add_argument("--start-date", type=str, default="2025-01-01", help="Start date for timestamp range (YYYY-MM-DD)")
    parser.add_argument("--end-date", type=str, default=None, help="End date for timestamp range (YYYY-MM-DD, default: now)")
    args = parser.parse_args()

    if args.rows <= 0:
        print("--rows must be > 0")
        sys.exit(1)

    # Parse date range
    start_date = datetime.strptime(args.start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if args.end_date:
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        end_date = datetime.now(timezone.utc)

    print(f"Preparing to generate {args.rows} rows")
    print(f"Timestamp range: {start_date.date()} to {end_date.date()}")

    rows = [gen_row(i, start_date, end_date) for i in range(args.rows)]

    if args.dry_run:
        out_file = "out.ndjson"
        print(f"Writing NDJSON to {out_file}...")
        with open(out_file, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        print("Done: write complete. Use `bq load --source_format=NEWLINE_DELIMITED_JSON` to load into BigQuery")
        return

    if bigquery is None:
        print("google-cloud-bigquery library not found. Install with: pip install google-cloud-bigquery")
        sys.exit(1)

    if not args.project or not args.dataset or not args.table:
        print("project, dataset and table must be provided via flags or environment (BQ_PROJECT_ID,BQ_DATASET,BQ_TABLE)")
        sys.exit(1)

    client = bigquery.Client(project=args.project)

    # ensure dataset/table exist
    ensure_table(client, args.dataset, args.table)

    print("Inserting rows in batches...")
    ok = insert_in_batches(client, args.dataset, args.table, rows, batch_size=args.batch_size)
    if ok:
        print(f"Successfully inserted {args.rows} rows into {args.project}.{args.dataset}.{args.table}")
    else:
        print("Insertion failed. See errors above.")


if __name__ == "__main__":
    main()
