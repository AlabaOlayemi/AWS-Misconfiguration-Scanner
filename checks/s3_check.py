import boto3

def check_public_buckets():
    findings = []

    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        name = bucket['Name']
        try:
            # Check Block Public Access settings — this is the RIGHT way
            pab = s3.get_public_access_block(Bucket=name)
            config = pab['PublicAccessBlockConfiguration']

            # If ANY of these four are False, the bucket is exposed
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                findings.append({
                    'severity': 'CRITICAL',
                    'resource': name,
                    'issue': 'S3 bucket has Block Public Access disabled',
                    'fix': 'Go to S3 → Permissions → Block Public Access → Enable all 4 settings'
                })

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            # No Block Public Access config exists at all — also dangerous
            findings.append({
                'severity': 'CRITICAL',
                'resource': name,
                'issue': 'S3 bucket has no Block Public Access configuration — fully exposed',
                'fix': 'Go to S3 → Permissions → Block Public Access → Enable all 4 settings'
            })
        except Exception:
            pass

    return findings