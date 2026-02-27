"""
Cloud-Sentinel: AWS Infrastructure Setup Script
Run this ONCE before starting the Flask app.

Creates:
  - DynamoDB table: CloudSentinelLogs   (SiteURL + Timestamp)
  - DynamoDB table: CloudSentinelUsers  (UserId  + CreatedAt)
  - SNS topic:      CloudSentinelAlerts
  - IAM policy:     CloudSentinelLambdaPolicy  (for the EC2 instance role)

Usage:
    python aws_setup.py
    python aws_setup.py --delete   # tear down all resources
"""

import argparse
import json
import sys
import time

import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ap-south-2"

dynamodb = boto3.client("dynamodb", region_name=AWS_REGION)
sns      = boto3.client("sns",      region_name=AWS_REGION)
iam      = boto3.client("iam",      region_name=AWS_REGION)
sts      = boto3.client("sts",      region_name=AWS_REGION)


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def account_id():
    return sts.get_caller_identity()["Account"]


def table_exists(name):
    try:
        dynamodb.describe_table(TableName=name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise


def wait_for_table(name, desired_state="ACTIVE"):
    print(f"  Waiting for {name} → {desired_state} ...", end="", flush=True)
    while True:
        try:
            status = dynamodb.describe_table(TableName=name)["Table"]["TableStatus"]
            if status == desired_state:
                print(" ✅")
                return
            print(".", end="", flush=True)
            time.sleep(2)
        except ClientError:
            break


# ══════════════════════════════════════════════════════════════
# CREATE
# ══════════════════════════════════════════════════════════════
def create_logs_table():
    name = "CloudSentinelLogs"
    if table_exists(name):
        print(f"[dynamo] {name} already exists — skipping.")
        return

    print(f"[dynamo] Creating {name} ...")
    dynamodb.create_table(
        TableName=name,
        AttributeDefinitions=[
            {"AttributeName": "SiteURL",   "AttributeType": "S"},
            {"AttributeName": "Timestamp", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "SiteURL",   "KeyType": "HASH"},
            {"AttributeName": "Timestamp", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[
            {"Key": "Project", "Value": "CloudSentinel"},
            {"Key": "Region",  "Value": AWS_REGION},
        ],
    )
    wait_for_table(name)


def create_users_table():
    name = "CloudSentinelUsers"
    if table_exists(name):
        print(f"[dynamo] {name} already exists — skipping.")
        return

    print(f"[dynamo] Creating {name} ...")
    dynamodb.create_table(
        TableName=name,
        AttributeDefinitions=[
            {"AttributeName": "UserId",    "AttributeType": "S"},
            {"AttributeName": "CreatedAt", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "UserId",    "KeyType": "HASH"},
            {"AttributeName": "CreatedAt", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[
            {"Key": "Project", "Value": "CloudSentinel"},
        ],
    )
    wait_for_table(name)


def create_sns_topic():
    print("[sns] Creating CloudSentinelAlerts topic ...")
    resp = sns.create_topic(
        Name="CloudSentinelAlerts",
        Tags=[{"Key": "Project", "Value": "CloudSentinel"}],
    )
    arn = resp["TopicArn"]
    print(f"[sns] ✅ Topic ARN: {arn}")
    return arn


def create_iam_policy():
    acct = account_id()
    policy_name = "CloudSentinelLambdaPolicy"
    topic_arn   = f"arn:aws:sns:{AWS_REGION}:{acct}:CloudSentinelAlerts"

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DynamoDBAccess",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:PutItem",
                    "dynamodb:GetItem",
                    "dynamodb:Scan",
                    "dynamodb:Query",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                ],
                "Resource": [
                    f"arn:aws:dynamodb:{AWS_REGION}:{acct}:table/CloudSentinelLogs",
                    f"arn:aws:dynamodb:{AWS_REGION}:{acct}:table/CloudSentinelUsers",
                ],
            },
            {
                "Sid": "SNSPublish",
                "Effect": "Allow",
                "Action": [
                    "sns:Publish",
                    "sns:Subscribe",
                    "sns:Unsubscribe",
                    "sns:GetSubscriptionAttributes",
                    "sns:ListSubscriptionsByTopic",
                ],
                "Resource": topic_arn,
            },
            {
                "Sid": "STSGetCallerIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            },
            {
                "Sid": "CloudWatchLogs",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {
                "Sid": "S3Snapshots",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:ListBucket",
                ],
                "Resource": [
                    f"arn:aws:s3:::cloud-sentinel-snapshots-{acct}",
                    f"arn:aws:s3:::cloud-sentinel-snapshots-{acct}/*",
                ],
            },
        ],
    }

    print(f"[iam] Creating policy {policy_name} ...")
    try:
        resp = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
            Description="Cloud-Sentinel: allows Lambda/EC2 to access DynamoDB, SNS, S3, CloudWatch",
            Tags=[{"Key": "Project", "Value": "CloudSentinel"}],
        )
        arn = resp["Policy"]["Arn"]
        print(f"[iam] ✅ Policy ARN: {arn}")
        return arn
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"[iam] Policy {policy_name} already exists — skipping.")
            return f"arn:aws:iam::{acct}:policy/{policy_name}"
        raise


def create_s3_bucket():
    import boto3 as b3
    acct   = account_id()
    bucket = f"cloud-sentinel-snapshots-{acct}"
    s3     = b3.client("s3", region_name=AWS_REGION)

    print(f"[s3] Creating bucket {bucket} ...")
    try:
        if AWS_REGION == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": AWS_REGION},
            )
        # Block all public access
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True,
            },
        )
        print(f"[s3] ✅ Bucket created: {bucket}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"[s3] Bucket {bucket} already exists — skipping.")
        else:
            raise


# ══════════════════════════════════════════════════════════════
# DELETE (teardown)
# ══════════════════════════════════════════════════════════════
def delete_table(name):
    print(f"[dynamo] Deleting {name} ...")
    try:
        dynamodb.delete_table(TableName=name)
        wait_for_table(name, desired_state="DELETED")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f"[dynamo] {name} not found — skipping.")
        else:
            raise


def delete_sns_topic():
    acct      = account_id()
    topic_arn = f"arn:aws:sns:{AWS_REGION}:{acct}:CloudSentinelAlerts"
    print(f"[sns] Deleting topic {topic_arn} ...")
    try:
        sns.delete_topic(TopicArn=topic_arn)
        print("[sns] ✅ Deleted.")
    except ClientError as e:
        print(f"[sns] {e.response['Error']['Code']} — skipping.")


def delete_iam_policy():
    acct        = account_id()
    policy_arn  = f"arn:aws:iam::{acct}:policy/CloudSentinelLambdaPolicy"
    print(f"[iam] Deleting policy {policy_arn} ...")
    try:
        # Detach from all entities first
        for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=policy_arn):
            for role in page.get("PolicyRoles", []):
                iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=policy_arn)
        iam.delete_policy(PolicyArn=policy_arn)
        print("[iam] ✅ Deleted.")
    except ClientError as e:
        print(f"[iam] {e.response['Error']['Code']} — skipping.")


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def setup():
    print("=" * 55)
    print("  Cloud-Sentinel AWS Infrastructure Setup")
    print(f"  Region: {AWS_REGION}")
    print("=" * 55)
    create_logs_table()
    create_users_table()
    create_sns_topic()
    create_iam_policy()
    create_s3_bucket()
    print()
    print("=" * 55)
    print("  ✅  Setup complete!")
    print("  Next: python app.py")
    print("  First run: visit http://<EC2-IP>:5000/setup")
    print("=" * 55)


def teardown():
    print("=" * 55)
    print("  Cloud-Sentinel AWS Teardown")
    print("=" * 55)
    delete_table("CloudSentinelLogs")
    delete_table("CloudSentinelUsers")
    delete_sns_topic()
    delete_iam_policy()
    print("✅ Teardown complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud-Sentinel AWS Setup")
    parser.add_argument("--delete", action="store_true", help="Tear down all AWS resources")
    args = parser.parse_args()

    if args.delete:
        teardown()
    else:
        setup()