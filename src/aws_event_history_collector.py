import argparse
import json
import os
from datetime import datetime, timedelta, timezone


def parse_cloudtrail_event(event):
    cloudtrail_event = event.get("CloudTrailEvent")

    if not cloudtrail_event:
        return None

    try:
        return json.loads(cloudtrail_event)
    except json.JSONDecodeError:
        return None


def collect_event_history(region, hours, max_events, profile=None):
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError as exc:
        raise RuntimeError("boto3 is required. Install it with: pip install boto3") from exc

    try:
        if profile:
            session = boto3.Session(profile_name=profile, region_name=region)
        else:
            session = boto3.Session(region_name=region)

        client = session.client("cloudtrail", region_name=region)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        paginator = client.get_paginator("lookup_events")

        records = []

        page_iterator = paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={
                "MaxItems": max_events,
                "PageSize": 50,
            },
        )

        for page in page_iterator:
            for event in page.get("Events", []):
                parsed_event = parse_cloudtrail_event(event)

                if parsed_event:
                    records.append(parsed_event)

        return {
            "Records": records,
            "collector_metadata": {
                "source": "AWS CloudTrail Event History",
                "region": region,
                "hours": hours,
                "max_events": max_events,
                "collected_at": end_time.isoformat(),
            },
        }

    except NoCredentialsError as exc:
        raise RuntimeError(
            "AWS credentials were not found. Configure AWS CLI first with: aws configure"
        ) from exc
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"AWS CloudTrail collection failed: {exc}") from exc


def write_output(data, output_file):
    output_dir = os.path.dirname(output_file)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(
        description="Collect recent AWS CloudTrail Event History and save it as CloudTrail-style JSON."
    )

    parser.add_argument(
        "--region",
        default=os.getenv("AWS_REGION", "us-east-1"),
        help="AWS region to query. Default: us-east-1",
    )

    parser.add_argument(
        "--hours",
        type=int,
        default=int(os.getenv("CLOUDTRAIL_LOOKUP_HOURS", "24")),
        help="How many recent hours to collect. Default: 24",
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=int(os.getenv("CLOUDTRAIL_MAX_EVENTS", "100")),
        help="Maximum number of events to collect. Default: 100",
    )

    parser.add_argument(
        "--profile",
        default=os.getenv("AWS_PROFILE"),
        help="Optional AWS CLI profile name.",
    )

    parser.add_argument(
        "--output",
        default="data/raw/aws_cloudtrail_event_history.json",
        help="Output JSON file path.",
    )

    args = parser.parse_args()

    data = collect_event_history(
        region=args.region,
        hours=args.hours,
        max_events=args.max_events,
        profile=args.profile,
    )

    write_output(data, args.output)

    print(f"Collected events: {len(data.get('Records', []))}")
    print(f"Output file: {args.output}")


if __name__ == "__main__":
    main()
