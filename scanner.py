from checks.s3_check import check_public_buckets
from checks.sg_check import check_open_security_groups
from checks.iam_check import check_iam_mfa
from report import print_report

print("Starting AWS security scan...")

all_findings = []  # one big list to collect ALL findings

print("Checking S3 buckets...")
all_findings.extend(check_public_buckets())

print("Checking security groups...")
all_findings.extend(check_open_security_groups())

print("Checking IAM users for MFA...")
all_findings.extend(check_iam_mfa())

print_report(all_findings)  # print the final coloured report