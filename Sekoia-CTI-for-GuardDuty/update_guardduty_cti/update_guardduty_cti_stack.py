import aws_cdk as cdk
from aws_cdk import Duration, Stack
from aws_cdk import aws_events as events
from aws_cdk import aws_guardduty as gd
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from aws_cdk import custom_resources as cr
from constructs import Construct


class SekoiaCTIGuardDutyStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Parameters
        parameter_APIKEY = cdk.CfnParameter(
            self,
            "APIKEYParameter",
            description="Please enter the SEKOIA.IO API KEY. It is provided by SEKOIA.IO at subscription.",
        )

        parameter_DETECTOR = cdk.CfnParameter(
            self,
            "DETECTORParameter",
            description="Please enter your DetectorId. You can find it in GuardDuty parameter once GuardDuty is enabled.",
        )

        # S3
        my_bucket = s3.CfnBucket(
            self,
            "SEKOIA_CTI_Bucket",
            bucket_name="sekoia-cti",
            access_control="Private",
            notification_configuration=s3.CfnBucket.NotificationConfigurationProperty(
                event_bridge_configuration=s3.CfnBucket.EventBridgeConfigurationProperty(
                    event_bridge_enabled=True
                )
            ),
            public_access_block_configuration=s3.CfnBucket.PublicAccessBlockConfigurationProperty(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
        )

        # IAM & Policies
        copy_lambda_role = iam.CfnRole(
            self,
            "CopySekoiaLambdaGuardDutyRole",
            role_name="CopySekoiaLambdaGuardDutyRole",
            description="This role is specific to lambda function named CopySekoiaLambdaGuardDuty. It allows to write logs, to RW on a specific bucket.",
            assume_role_policy_document={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        )

        copy_lambda_policy = iam.CfnPolicy(
            self,
            "CopySekoiaLambdaGuardDutyPolicy",
            policy_name="CopySekoiaLambdaGuardDutyPolicy",
            roles=["CopySekoiaLambdaGuardDutyRole"],
            policy_document={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:"
                        + self.region
                        + ":"
                        + self.account
                        + ":log-group:/aws/lambda/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": my_bucket.attr_arn + "/*",
                    },
                ],
            },
        )

        update_lambda_role = iam.CfnRole(
            self,
            "UpdateSekoiaCTIGuardDutyRole",
            role_name="UpdateSekoiaCTIGuardDutyRole",
            description="This role is specific to lambda function named UpdateSekoiaCTIGuardDuty. It allows to write logs, to RW on a specific bucket and update GuardDuty.",
            assume_role_policy_document={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        )

        update_lambda_policy = iam.CfnPolicy(
            self,
            "UpdateSekoiaCTIGuardDutyPolicy",
            policy_name="UpdateSekoiaCTIGuardDutyPolicy",
            roles=["UpdateSekoiaCTIGuardDutyRole"],
            policy_document={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:"
                        + self.region
                        + ":"
                        + self.account
                        + ":log-group:/aws/lambda/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": my_bucket.attr_arn + "/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "guardduty:ListDetectors",
                            "guardduty:GetThreatIntelSet",
                            "guardduty:ListThreatIntelSets",
                            "guardduty:UpdateThreatIntelSet",
                        ],
                        "Resource": "arn:aws:guardduty:"
                        + self.region
                        + ":"
                        + self.account
                        + ":detector/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PutRolePolicy",
                            "iam:DeleteRolePolicy",
                        ],
                        "Resource": "arn:aws:iam::"
                        + self.account
                        + ":role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
                    },
                ],
            },
        )

        # Lambda
        copy_lambda = lambda_.CfnFunction(
            self,
            "CopySEKOIALambdaGuardDuty",
            code=lambda_.CfnFunction.CodeProperty(
                zip_file="""
import boto3
import requests
import os
BUCKET_NAME = os.environ.get("BUCKET_NAME")
def handler(event, context):
    r = requests.get("https://raw.githubusercontent.com/maxime-el-haddari/testing-lambda/main/sekoia-update-cti-guardduty.zip")
    with open("/tmp/sekoia-update-cti-guardduty.zip", "wb") as f:
        f.write(r.content)
    s3_client = boto3.client("s3")
    s3_client.upload_file("/tmp/sekoia-update-cti-guardduty.zip", BUCKET_NAME, "sekoia-update-cti-guardduty.zip")
            """
            ),
            role=copy_lambda_role.attr_arn,
            runtime="python3.7",
            handler="index.handler",
            package_type="Zip",
            function_name="CopySekoiaLambdaGuardDuty",
            environment=lambda_.CfnFunction.EnvironmentProperty(
                variables={
                    "BUCKET_NAME": my_bucket.bucket_name,
                }
            ),
            timeout=10,
        )
        update_lambda = lambda_.CfnFunction(
            self,
            "UpdateSEKOIACTIGuardDuty",
            code=lambda_.CfnFunction.CodeProperty(
                s3_bucket=my_bucket.bucket_name,
                s3_key="sekoia-update-cti-guardduty.zip",
            ),
            role=update_lambda_role.attr_arn,
            runtime="python3.7",
            handler="app.handler",
            package_type="Zip",
            function_name="UpdateSekoiaCTIGuardDuty",
            environment=lambda_.CfnFunction.EnvironmentProperty(
                variables={
                    "API_KEY": parameter_APIKEY.value_as_string,
                    "BUCKET_ENDPOINT": my_bucket.attr_website_url,
                    "BUCKET_NAME": my_bucket.bucket_name,
                }
            ),
            timeout=20,
        )

        # Custom Ressources
        copy_trigger = cr.AwsCustomResource(
            scope=self,
            id="invoke_lambda",
            policy=(
                cr.AwsCustomResourcePolicy.from_statements(
                    statements=[
                        iam.PolicyStatement(
                            actions=["lambda:InvokeFunction"],
                            effect=iam.Effect.ALLOW,
                            resources=[copy_lambda.attr_arn],
                        )
                    ]
                )
            ),
            timeout=Duration.minutes(15),
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": copy_lambda.function_name,
                    "InvocationType": "Event",
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    "JobSenderTriggerPhysicalId"
                ),
            ),
            on_update=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": copy_lambda.function_name,
                    "InvocationType": "Event",
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    "JobSenderTriggerPhysicalId"
                ),
            ),
            function_name="CopyLambdaGuardDutyEvent",
        )
        update_lambda.node.add_dependency(copy_trigger)

        # BridgeEvents
        event_rule = events.CfnRule(
            self,
            "SEKOIALambdaSchedulerGuardDuty",
            description="Schedule rule to trigger Lambda UpdateSekoiaCTIGuardDuty",
            name="SEKOIALambdaSchedulerGuardDuty",
            state="ENABLED",
            schedule_expression="rate(30 minutes)",
            targets=[
                events.CfnRule.TargetProperty(
                    arn=update_lambda.attr_arn, id="UpdateSekoiaCTIGuardDuty"
                )
            ],
        )

        # GuardDuty
        threat_intel_set = gd.CfnThreatIntelSet(
            self,
            "SekoiaCTIThreatIntelSet",
            activate=False,
            detector_id=parameter_DETECTOR.value_as_string,
            format="TXT",
            location=f"s3://{my_bucket.bucket_name}/intelset.txt",
            name="SEKOIA Threat Intel",
        )

        # Permissions
        lambda_permission = lambda_.CfnPermission(
            self,
            "LambdaPermissionInvoke",
            action="lambda:InvokeFunction",
            principal="events.amazonaws.com",
            function_name="UpdateSekoiaCTIGuardDuty",
            source_arn=event_rule.attr_arn,
        )
