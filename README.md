# AWS Misconfiguration Scanner

A Python security tool that automatically scans an AWS account
for common misconfigurations and produces a prioritised findings
report — helping teams catch vulnerabilities before attackers do.

## What it detects
| Finding | Severity | Description |
|---------|----------|-------------|
| Public S3 buckets | CRITICAL | Block Public Access disabled |
| Open security groups | HIGH | Port exposed to 0.0.0.0/0 |
| IAM users without MFA | MEDIUM | No MFA device configured |

## Setup
```bash
pip install boto3 colorama awscli
aws configure
python3 scanner.py
```

## Sample output
```
[CRITICAL] my-test-bucket
  Issue : S3 bucket has Block Public Access disabled
  Fix   : Go to S3 → Permissions → Block Public Access → Enable all

[MEDIUM] scanner-user
  Issue : IAM user has no MFA device configured
  Fix   : IAM → Users → Security Credentials → Assign MFA device
```

## Skills demonstrated
Python · AWS boto3 · IAM · S3 · Security Groups
Cloud Security · CSPM concepts · Boto3 API

## Author
Alaba Olayemi — Cloud Security Engineer (in progress)
https://github.com/AlabaOlayemi/AWS-Misconfiguration-Scanner



