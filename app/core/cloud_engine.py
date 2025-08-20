# -*- coding: utf-8 -*-
import asyncio
import boto3
from typing import Dict, Any

class CloudEngine:
    """Handles connections and data fetching from cloud providers."""

    async def get_aws_network_inventory(self, region: str, aws_access_key: str, aws_secret_key: str) -> Dict[str, Any]:
        """Fetches network resources from an AWS account."""
        
        def do_fetch():
            """Synchronous function to run in a thread."""
            try:
                session = boto3.Session(
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
                ec2 = session.client('ec2')
                
                vpcs = ec2.describe_vpcs()['Vpcs']
                subnets = ec2.describe_subnets()['Subnets']
                sgs = ec2.describe_security_groups()['SecurityGroups']

                inventory = {'vpcs': {}, 'subnets': {}, 'security_groups': {}}
                
                for vpc in vpcs:
                    inventory['vpcs'][vpc['VpcId']] = {
                        'cidr': vpc['CidrBlock'],
                        'is_default': vpc.get('IsDefault', False),
                        'tags': {t['Key']: t['Value'] for t in vpc.get('Tags', [])}
                    }

                for subnet in subnets:
                    inventory['subnets'][subnet['SubnetId']] = {
                        'vpc_id': subnet['VpcId'],
                        'cidr': subnet['CidrBlock'],
                        'az': subnet['AvailabilityZone'],
                        'tags': {t['Key']: t['Value'] for t in subnet.get('Tags', [])}
                    }

                for sg in sgs:
                    inventory['security_groups'][sg['GroupId']] = {
                        'name': sg['GroupName'],
                        'vpc_id': sg.get('VpcId', 'N/A'),
                        'description': sg['Description'],
                        'ingress_rules': sg.get('IpPermissions', []),
                        'egress_rules': sg.get('IpPermissionsEgress', [])
                    }

                return inventory
            except Exception as e:
                # Catch Boto3/AWS errors and return them
                return {'error': str(e)}

        return await asyncio.get_running_loop().run_in_executor(None, do_fetch)