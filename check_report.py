
import csv
from pathlib import Path

report_path = Path("reports/live_traffic_report.csv")

if not report_path.exists():
    print("CSV report not found!")
else:
    with report_path.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    print("NETSENTRY - CSV REPORT CHECK")
    print("-" * 35)
    print(f"Report: {report_path}")
    print(f"Total records: {len(rows)}")

    if rows:
        print("Columns:", ", ".join(rows[0].keys()))
        print("\nFirst record:")
        for key, value in rows[0].items():
            print(f"{key}: {value}")
    else:
        print("The report is empty.")
