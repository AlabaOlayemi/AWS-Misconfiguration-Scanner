import boto3

def check_iam_mfa():
    findings = []
    iam = boto3.client('iam')  # connect to the user/permissions part of AWS
    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        # if the list is empty, no MFA is set up — like no lock on the door
        if not mfa_devices:
            findings.append({
                'severity': 'MEDIUM',
                'resource': username,
                'issue': 'IAM user has no MFA device configured',
                'fix': 'Go to IAM → Users → Security Credentials → Assign MFA device'
            })
    return findings