import csv
import json
import argparse


def normalize_indicator(value):
    """Convert defanged IOC indicators to their normal form."""
    if not value:
        return value

    value = value.strip()

    # Convert defanged protocols
    value = value.replace("hxxps://", "https://")
    value = value.replace("hxxp://", "http://")

    # Convert defanged dots
    value = value.replace("[.]", ".")

    return value


def csv_to_json(input_file, output_file):
    data = []

    with open(input_file, mode="r", encoding="utf-8-sig", newline="") as csv_file:
        # Detect CSV delimiter
        sample = csv_file.read(4096)
        csv_file.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(csv_file, dialect=dialect)

        # Clean column names
        if reader.fieldnames:
            reader.fieldnames = [
                field.strip().lower() if field else field
                for field in reader.fieldnames
            ]

        print("CSV columns found:", reader.fieldnames)

        # Validate required columns
        required_columns = {"type", "indicator"}

        if not required_columns.issubset(set(reader.fieldnames or [])):
            raise ValueError(
                f"CSV must contain columns: {required_columns}. "
                f"Found: {reader.fieldnames}"
            )

        has_description_column = "description" in (reader.fieldnames or [])

        for row in reader:
            ioc_type = row["type"].strip()
            indicator = normalize_indicator(row["indicator"])

            # Skip empty rows
            if not ioc_type or not indicator:
                continue

            description = ""
            if has_description_column:
                description = (row.get("description") or "").strip()

            data.append({
                "type": ioc_type,
                "value": indicator,
                "description": description
            })

    with open(output_file, mode="w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=4)

    print(f"Converted {len(data)} records.")
    print(f"JSON saved to: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert IOC CSV file to JSON"
    )

    parser.add_argument(
        "input_file",
        help="Path to the input CSV file"
    )

    parser.add_argument(
        "output_file",
        help="Path to the output JSON file"
    )

    args = parser.parse_args()

    csv_to_json(args.input_file, args.output_file)
