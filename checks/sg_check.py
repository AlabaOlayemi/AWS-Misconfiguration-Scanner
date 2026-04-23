import boto3

def check_open_security_groups():
    findings = []
    ec2 = boto3.client('ec2')  # connect to the compute part of AWS
    sgs = ec2.describe_security_groups()['SecurityGroups']

    for sg in sgs:
        for rule in sg['IpPermissions']:
            for ip_range in rule.get('IpRanges', []):
                # 0.0.0.0/0 means "every computer on the internet can connect"
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort', 'all')
                    findings.append({
                        'severity': 'HIGH',
                        'resource': sg['GroupId'],
                        'issue': f'Port {port} open to entire internet (0.0.0.0/0)',
                        'fix': 'Restrict the source IP to only your office/home IP'
                    })
    return findings