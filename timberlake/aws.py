import boto3
import botocore.client
import botocore.waiter
import json
import time
import io
import zipfile

from .log import logger
from .types import List, Tuple, BotoResource, BotoClient, BotoSession, BotoClientOrSession
from .common import gen_rand_string


def guardduty_ipsetactive_waiter_model(*args, **kwargs):
    return botocore.waiter.WaiterModel(
        {
            "version": 2,
            "waiters": {
                "IpSetActive": {
                    "delay": 1,
                    "operation": "GetIpSet",
                    "maxAttempts": 20,
                    "acceptors": [
                        {"state": "success", "matcher": "path", "expected": True, "argument": "Status == 'ACTIVE'"}
                    ],
                }
            },
        }
    )


def ssm_instanceavailable_waiter_model(*args, **kwargs):
    instance_id = kwargs.get("instance_id")
    return botocore.waiter.WaiterModel(
        {
            "version": 2,
            "waiters": {
                "InstanceAvailable": {
                    "delay": 2,
                    "operation": "DescribeInstanceInformation",
                    "maxAttempts": 20,
                    "acceptors": [
                        {
                            "state": "success",
                            "matcher": "path",
                            "expected": True,
                            # TODO: better to do like this or use underlying API's filtering on the instance id?
                            "argument": f"length(InstanceInformationList[?InstanceId == '{instance_id}']) > `0`",
                        }
                    ],
                }
            },
        }
    )


class CustomWaiters:
    # see also https://kentzo.medium.com/customizing-botocore-waiters-83badbfd6399
    # iam reference waiter https://github.com/boto/botocore/blob/develop/botocore/data/iam/2010-05-08/waiters-2.json
    @staticmethod
    def get_waiter(waiter_name: str, client, *model_args, **model_kwargs):
        """
        return a waiter instance using a child waiter
        waiter_name = <service>.<operation>
        """
        service, operation = waiter_name.split(".")
        waiter_model_fn = getattr(getattr(CustomWaiters, service), operation)
        waiter_model = waiter_model_fn(*model_args, **model_kwargs)
        return botocore.waiter.create_waiter_with_client(operation, waiter_model, client)

    class GuardDuty:
        # IpSetActive waits for an IP set to be available based on GuardDuty GetIpSet
        IpSetActive = guardduty_ipsetactive_waiter_model

    class SSM:
        # InstanceAvailable waits for an EC2 instance to be available in the SSM inventory
        #   based on SSM DescribeInstanceInformation + a provided instance ID model kwarg
        InstanceAvailable = ssm_instanceavailable_waiter_model


class Primitives:
    @staticmethod
    def call_api_by_permission_name(
        permission: str, session: BotoSession, user_agent: str = None, region: str = None, **kwargs
    ):
        # given a permissions in the format service:action, create a boto3 client then
        # call that action
        service, operation = permission.split(":")
        client = session.client(service, region_name=region)
        if user_agent:
            client.meta.config.user_agent = user_agent
        fn_name = [k for k, v in client.meta.method_to_api_mapping.items() if v == operation][0]
        fn = getattr(client, fn_name)
        return fn(**kwargs)

    # TODO: these methods should have a special decorator that injects
    #   a first kwarg of client/session then converts that to either a
    #   client/session/resource based on a decorator argument
    #   example:
    #       @client_or_session(creates=Boto.Client)
    #       def foo(...):
    #           injected: BotoClient  <-- injected resource of supplied type
    #
    # TODO: alternatively every action here should just take a session/profile instead of a client or client/session
    #   goal is to standardize on either client or session (or something else)
    #   rather than allow all then convert
    class STS:
        @staticmethod
        def get_account_number(sts_client: BotoClient):
            """given an STS client, retrieve the account number its associated with"""
            return sts_client.get_access_key_info(AccessKeyId=sts_client._request_signer._credentials.access_key)[
                "Account"
            ]

    class S3:
        @staticmethod
        def create_bucket(s3: BotoClientOrSession) -> str:
            """creates a bucket with a random 32 character name"""
            bucket_name = gen_rand_string(length=32)
            resource = get_resource_from_client_or_session(s3, service="s3")
            bucket = resource.Bucket(bucket_name)
            bucket.create()
            return bucket_name

        @staticmethod
        def create_cloudtrail_bucket(s3_client: BotoClient, trail_name: str) -> str:
            """create a bucket with a random name thats configured to allow writing by CloudTrail"""
            bucket_name = Primitives.S3.create_bucket(s3_client)
            region = s3_client.meta.region_name
            account_number = Primitives.STS.get_account_number(
                sts_client=boto_client_to_client(client=s3_client, new_service="sts")
            )

            policy = CannedPolicies.ResourcePolicies.cloudtrail_bucket_policy(
                bucket_name=bucket_name, region=region, account_number=account_number, trail_name=trail_name
            )
            s3_client.put_bucket_policy(Bucket=bucket_name, Policy=policy)
            return bucket_name

        @staticmethod
        def delete_bucket(s3: BotoClientOrSession, bucket_name: str):
            """deletes all objects in a bucket then the bucket itself"""
            resource = get_resource_from_client_or_session(s3, service="s3")
            bucket = resource.Bucket(bucket_name)
            bucket.objects.all().delete()
            bucket.delete()

        @staticmethod
        def upload_str_to_bucket(s3: BotoClientOrSession, bucket_name: str, contents: str, key: str):
            """upload a provided string to a bucket as a new object"""
            resource = get_resource_from_client_or_session(s3, service="s3")
            fileobj = io.BytesIO(contents.encode())
            resource.Bucket(bucket_name).Object(key).upload_fileobj(fileobj)
            fileobj.close()

    class EC2:
        @staticmethod
        def get_latest_ubuntu_ami_id(ec2_client: BotoClient) -> str:
            """get the latest AMI ID for Ubuntu 22.04"""
            amis = ec2_client.describe_images(
                Owners=["099720109477"],  # Canonical
                Filters=[
                    {"Name": "name", "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]},
                    {"Name": "virtualization-type", "Values": ["hvm"]},
                ],
            )["Images"]
            amis_sorted = sorted(amis, key=lambda x: x["CreationDate"], reverse=True)
            image_id = amis_sorted[0]["ImageId"]
            return image_id

        @staticmethod
        def create_ec2_instance(ec2_client: BotoClient, image_id: str = None, **run_kwargs) -> dict:
            """create an EC2 instance then wait for it to start"""
            if not image_id:
                image_id = Primitives.get_latest_ubuntu_ami_id(ec2_client=ec2_client)
            instances = ec2_client.run_instances(
                MaxCount=1, MinCount=1, ImageId=image_id, InstanceType="t2.micro", **run_kwargs
            )
            instance = instances["Instances"][0]
            ec2_client.get_waiter("instance_running").wait(InstanceIds=[instance["InstanceId"]])
            return instance

        @staticmethod
        def create_snapshot_for_instance(ec2_client: BotoClient, instance_id: str) -> str:
            """create a snapshot of an instance's volume"""
            volume_id = ec2_client.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
                "BlockDeviceMappings"
            ][0]["Ebs"]["VolumeId"]
            snapshot_id = ec2_client.create_snapshot(VolumeId=volume_id)["SnapshotId"]
            ec2_client.get_waiter("snapshot_completed").wait(SnapshotIds=[snapshot_id], WaiterConfig={"Delay": 10})
            return snapshot_id

        @staticmethod
        def create_ami_for_instance(ec2_client: BotoClient, instance_id: str, image_name: str) -> Tuple[str, str]:
            """create an AMI from an instance
            this implicitly creates a snapshot so both the AMI and snapshot ID are returned
            to allow for prpoper cleanup
            """
            ami_id = ec2_client.create_image(InstanceId=instance_id, Name=image_name)["ImageId"]
            ec2_client.get_waiter("image_available").wait(ImageIds=[ami_id])
            snapshot_id = ec2_client.describe_images(ImageIds=[ami_id])["Images"][0]["BlockDeviceMappings"][0]["Ebs"][
                "SnapshotId"
            ]

            return ami_id, snapshot_id

    class SSM:
        @staticmethod
        def run_ssm_command(ssm_client: BotoClient, commands: List[str], instance_id: str) -> str:
            """use SSM to run a shell command against an instance
            requires the instance to have the SSM agent installed
            """
            command_id = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                DocumentVersion="$DEFAULT",
                Parameters={"commands": commands},
            )["Command"]["CommandId"]
            ssm_client.get_waiter("command_executed").wait(CommandId=command_id, InstanceId=instance_id)
            command_output = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)[
                "StandardOutputContent"
            ]
            return command_output

    class IAM:
        @staticmethod
        def create_group(iam_client: BotoClient, group_name: str) -> str:
            """create a group under the path "/timberlake" """
            group = iam_client.create_group(Path="/timberlake/", GroupName=group_name)
            group_arn = group["Group"]["Arn"]
            return group_arn

        @staticmethod
        def create_user(iam_client: BotoClient, user_name: str) -> str:
            """create a user under the path "/timberlake" """
            user = iam_client.create_user(Path="/timberlake/", UserName=user_name)
            user_arn = user["User"]["Arn"]
            return user_arn

        @staticmethod
        def create_role(
            iam_client: BotoClient, role_name: str, trust_policy: str, permission_policy: str = None, wait: bool = True
        ) -> str:
            """create an IAM role under the path "/timberlake" with an (optional) inline policy"""
            role_arn = iam_client.create_role(
                Path="/timberlake/", RoleName=role_name, AssumeRolePolicyDocument=trust_policy
            )["Role"]["Arn"]
            if permission_policy:
                iam_client.put_role_policy(RoleName=role_name, PolicyName="policy", PolicyDocument=permission_policy)
            # the API does not expose a status of the role but its not available immediately so waiting after creation is required
            if wait:
                time.sleep(12)
            return role_arn

        @staticmethod
        def create_instance_role(iam_client: BotoClient, profile_name: str, **role_create_kwargs) -> Tuple[str, str]:
            """creates an instance profile under the path "/timberlake/" and the underlying role"""
            instance_profile_arn = iam_client.create_instance_profile(
                InstanceProfileName=profile_name, Path="/timberlake/"
            )["InstanceProfile"]["Arn"]
            role_arn = Primitives.IAM.create_role(
                iam_client=iam_client,
                role_name=role_create_kwargs.get("role_name"),
                trust_policy=role_create_kwargs.get("trust_policy"),
                permission_policy=role_create_kwargs.get("permission_policy"),
            )
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_create_kwargs.get("role_name")
            )
            return role_arn, instance_profile_arn

        @staticmethod
        def delete_role(iam: BotoClientOrSession, role_name: str):
            """delete all inline/attached policies from a role then delete the role"""
            delete_iam_principal(iam, principal_type="Role", principal_name=role_name)

        @staticmethod
        def delete_user(iam: BotoClientOrSession, user_name: str):
            """delete all inline/attached policies from a user then delete the user"""
            delete_iam_principal(iam, principal_type="User", principal_name=user_name)

        @staticmethod
        def delete_group(iam: BotoClientOrSession, group_name: str):
            group = get_resource_from_client_or_session(iam, service="iam").Group(group_name)
            delete_policies_from_iam_resource(group)
            [group.remove_user(UserName=user.name) for user in group.users.all()]
            group.delete()

    class GuardDuty:
        @staticmethod
        def create_ip_set(guardduty_client: BotoClient, detector_id: str, ipset_name: str, iplist_s3_url: str) -> str:
            """create an IpSet in GuardDuty from an S3 URL then wait for it to be active"""
            ip_set_id = guardduty_client.create_ip_set(
                DetectorId=detector_id, Name=ipset_name, Format="TXT", Location=iplist_s3_url, Activate=True
            )["IpSetId"]
            CustomWaiters.get_waiter(waiter_name="GuardDuty.IpSetActive", client=guardduty_client).wait(
                DetectorId=detector_id, IpSetId=ip_set_id
            )
            return ip_set_id

    class Lambda:
        @staticmethod
        def generate_lambda_py_function_zip() -> Tuple[str, bytes]:
            """generate a ZIP file containing a Python Lambda function
            function prints AWS credential environment variables
            returns the entrypoint and zip file (as bytes)
            does not call any AWS APIs
            """
            code = (
                "import os\n"
                """def lambda_handler(event, context):\n"""
                """\treturn {"session_token": os.environ["AWS_SESSION_TOKEN"], "access_key": os.environ["AWS_ACCESS_KEY_ID"], "secret_key": os.environ["AWS_SECRET_ACCESS_KEY"]}"""
            )
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
                func_file = zipfile.ZipInfo("lambda_function.py")
                func_file.external_attr = 0o777 << 16
                zipf.writestr(func_file, code)
            buffer.seek(0)
            buffer_val = buffer.read()
            buffer.close()
            return "lambda_function.lambda_handler", buffer_val

        @staticmethod
        def create_function(lambda_client: BotoClient, function_name: str, role_arn: str):
            """create a lambda function that prints its credentials and wait for it to be active"""
            handler, function_zip = Primitives.Lambda.generate_lambda_py_function_zip()
            function = lambda_client.create_function(
                FunctionName=function_name,
                Runtime="python3.8",
                Role=role_arn,
                Code=dict(ZipFile=function_zip),
                Handler=handler,
            )
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
            return function["FunctionArn"]

        @staticmethod
        def create_public_layer(lambda_client: BotoClient, layer_name: str) -> Tuple[str, str]:
            """create a Lambda layer and set the permissions to allow public version retrieval
            returns the layer version and layer version ARN
            """
            # example attack:
            #   https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/
            handler, function_zip = Primitives.Lambda.generate_lambda_py_function_zip()
            layer = lambda_client.publish_layer_version(
                LayerName=layer_name, Content=dict(ZipFile=function_zip), CompatibleRuntimes=["python3.8"]
            )
            layer_version = layer["Version"]
            layer_version_arn = layer["LayerVersionArn"]
            lambda_client.add_layer_version_permission(
                LayerName=layer_name,
                VersionNumber=layer_version,
                StatementId="stmt",
                Action="lambda:GetLayerVersion",
                Principal="*",
            )
            return layer_version, layer_version_arn

    class Route53:
        @staticmethod
        def create_hijack_zone(session: BotoSession, target_vpc_id: str, region_name: str = None) -> Tuple[str, str]:
            """Create a private Route53 zone and placeholder vpc
            then create an association to the provided vpc id
            For use with: https://blog.ryanjarv.sh/2019/05/24/backdooring-route53-with-cross-account-dns.html
            Returns the new zone id and vpc id
            """
            caller_ref = gen_rand_string(length=16)
            region_name = session.region_name if not region_name else region_name

            ec2 = session.client("ec2", region_name=region_name)
            vpc_id = ec2.create_vpc(CidrBlock="10.10.10.0/24")["Vpc"]["VpcId"]

            route53 = session.client("route53")
            zone_id = route53.create_hosted_zone(
                Name="example.com",
                HostedZoneConfig={"PrivateZone": True},
                CallerReference=caller_ref,
                VPC={"VPCId": vpc_id, "VPCRegion": region_name},
            )["HostedZone"]["Id"]
            route53.create_vpc_association_authorization(
                HostedZoneId=zone_id, VPC={"VPCId": target_vpc_id, "VPCRegion": region_name}
            )
            return zone_id, vpc_id

    class VPC:
        @staticmethod
        def create_vpc_with_logging(
            ec2_client: BotoClient, log_group: str, delivery_role_arn: str
        ) -> Tuple[str, List[str]]:
            """Create a VPC with flow logging to CloudWatch configured
            return the vpc id and flow log ids
            """
            vpc_id = ec2_client.create_vpc(CidrBlock="10.10.10.0/24")["Vpc"]["VpcId"]
            flow_log_ids = ec2_client.create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType="VPC",
                TrafficType="ALL",
                LogDestinationType="cloud-watch-logs",
                DeliverLogsPermissionArn=delivery_role_arn,
                LogGroupName=log_group,
            )["FlowLogIds"]
            return (
                vpc_id,
                flow_log_ids,
            )


class CannedPolicies:
    class PermissionPolicies:
        @staticmethod
        def allow_all() -> str:
            """Full access policy"""
            return """{
              "Version": "2012-10-17",
              "Statement": [
                  {
                      "Effect": "Allow",
                      "Action": "*",
                      "Resource": "*"
                  }
              ]
            }"""

        @staticmethod
        def allow_single(permission: str) -> str:
            """policy template for allowing a single permission (format of service:action)"""
            return f"""{{
                "Version": "2012-10-17",
                "Statement": [
                    {{
                        "Sid": "1",
                        "Effect": "Allow",
                        "Action": "{permission}",
                        "Resource": "*"
                    }}
                ]
            }}"""

        @staticmethod
        def cloudwatch_basic() -> str:
            """basic polict for writing to cloudwatch"""
            return """{
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams"
                  ],
                  "Resource": "*"
                }
              ]
            }"""

    class TrustPolicies:
        @staticmethod
        def default_service_policy(service: str) -> str:
            """role trust policy for service roles (format of <service>.amazonaws.com"""
            return f"""{{
                "Version": "2012-10-17",
                "Statement": [
                    {{
                        "Effect": "Allow",
                        "Principal": {{
                            "Service": "{service}"
                        }},
                        "Action": "sts:AssumeRole"
                    }}
                ]
            }}"""

        @staticmethod
        def unrestricted_policy() -> str:
            """allow role assumption from anyone"""
            return """{
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal": {
                    "AWS": "*"
                  },
                  "Action": "sts:AssumeRole"
                }
              ]
            }"""

        @staticmethod
        def vpc_flow_policy(account_number: str) -> str:
            """basic flow log trust policy restricted to specific AWS account number"""
            return f"""{{
              "Version": "2012-10-17",
              "Statement": [
                {{
                  "Effect": "Allow",
                  "Principal": {{
                    "Service": "vpc-flow-logs.amazonaws.com"
                  }},
                  "Action": "sts:AssumeRole",
                  "Condition": {{
                    "StringEquals": {{
                      "aws:SourceAccount": "{account_number}"
                    }}
                  }}
                }}
              ]
            }}"""

    class ResourcePolicies:
        @staticmethod
        def cloudtrail_bucket_policy(bucket_name: str, region: str, account_number: str, trail_name: str) -> str:
            """S3 policy to allow writing by a specific trail"""
            return f"""{{
                "Version": "2012-10-17",
                "Statement": [
                    {{
                        "Sid": "AWSCloudTrailAclCheck20150319",
                        "Effect": "Allow",
                        "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::{bucket_name}",
                        "Condition": {{
                            "StringEquals": {{
                                "aws:SourceArn": "arn:aws:cloudtrail:{region}:{account_number}:trail/{trail_name}"
                            }}
                        }}
                    }},
                    {{
                        "Sid": "AWSCloudTrailWrite20150319",
                        "Effect": "Allow",
                        "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::{bucket_name}/AWSLogs/{account_number}/*",
                        "Condition": {{
                            "StringEquals": {{
                                "s3:x-amz-acl": "bucket-owner-full-control",
                                "aws:SourceArn": "arn:aws:cloudtrail:{region}:{account_number}:trail/{trail_name}"
                            }}
                        }}
                    }}
                ]
            }}"""

        @staticmethod
        def s3_all_access(bucket_name: str) -> str:
            """S3 policy to allow writing anything to anywhere"""
            return f"""{{
                "Version": "2008-10-17",
                "Id": "b2579fee-c68c-47f9-b3f3-0b3651f245f5",
                "Statement": [
                    {{
                        "Sid": "1",
                        "Effect": "Allow",
                        "Principal": {{
                            "AWS": "*"
                        }},
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::{bucket_name}/*"
                    }}
                ]
            }}"""


def serialization_placeholder(o) -> str:
    return f"<placeholder {type(o)}>"


def log_params(params, **kwargs):
    logger.info(
        json.dumps(
            {
                "service": kwargs.get("event_name").split(".")[-2],
                "operation": kwargs.get("event_name").split(".")[-1],
                "params": params,
                "region": kwargs.get("context")["client_region"],
            },
            default=serialization_placeholder,
        )
    )


def generate_boto_session(profile: str, **session_args) -> BotoSession:
    """create a boto session with appropriate logging callbacks and user-agent"""
    session = boto3.session.Session(profile_name=profile, **session_args)
    session._session.user_agent = lambda: "timberlake"
    # this is callback functionality exposed by the boto library
    # timberlake uses this to log the API parameters being sent to the control plane
    # unfortunately you need to hijack the session to be able to register the logging callback
    #   so creating a normal session wont get the logging benefit
    session.events.register("provide-client-params.*.*", log_params)
    # TODO: add another callback to inject tags via the TagSpecifications/Tags param
    #   if specified, add tag for timberlake. if not specified, add kwarg
    #   only inject if the method signature has TagSpecifications/Tags as a kwarg
    #       may need to use something like inspect.signature for this or check botocore json
    #   this callback should go before the param logging callback so new tags are captured in log
    #   should also independently log the changes
    #   TODO: how to handle TagSpecifications -> ResourceType? need to handle this or no?
    # look into how terraform does default tags at the provider level
    return session


def generate_aws_ctx(profiles: List[str]) -> dict:
    """create a context for use in test case block execution"""
    sessions = {}
    if profiles:
        sessions = {profile: generate_boto_session(profile=profile) for profile in profiles}
        # treat the first provided profile as the "default" if not provided
        if "default" not in sessions:
            sessions["default"] = generate_boto_session(profile=profiles[0])
    # TODO: add client(...) and resource(...) methods that take session + service as args
    return {
        "sessions": sessions,
        "boto3": boto3,
        "waiters": CustomWaiters,
        "primitives": Primitives,
        "generate_session": generate_boto_session,
        "policies": CannedPolicies,
    }


# below functions are a bit naive in the approach but they work for now

def boto_session_from_client(client: BotoClient, **session_kwargs) -> BotoSession:
    """given a boto client, create a new session from its credentials that also has Timberlake logging"""
    return generate_boto_session(
        aws_access_key_id=client._request_signer._credentials.access_key,
        aws_secret_access_key=client._request_signer._credentials.secret_key,
        aws_session_token=client._request_signer._credentials.token,
        region_name=client.meta.region_name if client.meta.region_name != "aws-global" else None,
        profile=None,
        **session_kwargs,
    )


def boto_client_to_resource(client: BotoClient, **session_kwargs) -> BotoResource:
    """given a boto client, return a boto resource for the same service"""
    session = boto_session_from_client(client=client, **session_kwargs)
    resource = session.resource(client.meta.service_model.service_name)
    return resource


def boto_client_to_client(client: BotoClient, new_service: str, **session_kwargs) -> BotoClient:
    """given a boto client for one service, create a new client for a different service"""

    # note: going from client to client by using client.meta.config doesn't work
    #   in cases of going from global<->regional services due to different endpoints.
    #       For example, going from IAM to EC2 results in an endpoint mismatch b/c
    #       IAM is a global service and EC2 is a regional service so there is no
    #       global EC2 endpoint URL (e.g. ec2.aws-global.amazonaws.com)
    #   It will however retain the registered logging events
    # This approach instead just pulls the bare minimum info (the credentials) and constructs
    #   a client from a newly generated session
    session = boto_session_from_client(client=client, **session_kwargs)
    client = session.client(new_service)
    return client


def get_resource_from_client_or_session(o: BotoClientOrSession, service: str) -> BotoResource:
    # given a boto client or session, create a boto resource
    if isinstance(o, botocore.client.BaseClient):
        resource = boto_client_to_resource(o)
    elif isinstance(o, boto3.session.Session):
        resource = o.resource(service)
    else:
        raise Exception(f"Unknown type {type(o).__name__}")

    return resource


def delete_policies_from_iam_resource(r: BotoResource):
    [policy.delete() for policy in r.policies.all()]
    [r.detach_policy(PolicyArn=policy.arn) for policy in r.attached_policies.all()]


def delete_iam_principal(iam: BotoClientOrSession, principal_type: str, principal_name: str):
    """delete an iam principal after removing all inline and attached policies"""
    resource = get_resource_from_client_or_session(iam, service="iam")
    principal_t = getattr(resource, principal_type)
    principal = principal_t(principal_name)
    delete_policies_from_iam_resource(principal)
    principal.delete()
