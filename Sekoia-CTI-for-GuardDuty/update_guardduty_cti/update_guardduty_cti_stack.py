from aws_cdk import (
    Duration,
    Stack,
    aws_lambda as lambda_,
    aws_s3 as s3,
    aws_events as events,
    aws_iam as iam,
    aws_guardduty as gd,
    custom_resources as cr,
)
from constructs import Construct
import aws_cdk as cdk


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

        parameter_BUCKET = cdk.CfnParameter(
            self,
            "BUCKETParameter",
            description="Please enter your Bucket ARN. One of your own bucket where the lambda code and the intelligence will be stored.",
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
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:" + self.region + ":" + self.account + ":log-group:/aws/lambda/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": "arn:aws:s3:::" + parameter_BUCKET.value_as_string + "/*",
                    },
                ],
            },
        )
        copy_lambda_policy.add_depends_on(copy_lambda_role)

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
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:" + self.region + ":" + self.account + ":log-group:/aws/lambda/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": "arn:aws:s3:::" + parameter_BUCKET.value_as_string + "/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "guardduty:ListDetectors",
                            "guardduty:GetThreatIntelSet",
                            "guardduty:ListThreatIntelSets",
                            "guardduty:UpdateThreatIntelSet",
                        ],
                        "Resource": "arn:aws:guardduty:" + self.region + ":" + self.account + ":detector/*",
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
        update_lambda_policy.add_depends_on(update_lambda_role)

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
    r = requests.get("https://raw.githubusercontent.com/SEKOIA-IO/sekoiaio-cti-aws-integration/main/lambda/sekoia-update-cti-guardduty.zip")
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
                    "BUCKET_NAME": parameter_BUCKET.value_as_string,
                }
            ),
            timeout=10,
        )
        update_lambda = lambda_.CfnFunction(
            self,
            "UpdateSEKOIACTIGuardDuty",
            code=lambda_.CfnFunction.CodeProperty(
                s3_bucket=parameter_BUCKET.value_as_string, s3_key="sekoia-update-cti-guardduty.zip"
            ),
            role=update_lambda_role.attr_arn,
            runtime="python3.7",
            handler="app.handler",
            package_type="Zip",
            function_name="UpdateSekoiaCTIGuardDuty",
            environment=lambda_.CfnFunction.EnvironmentProperty(
                variables={
                    "API_KEY": parameter_APIKEY.value_as_string,
                    "BUCKET_NAME": parameter_BUCKET.value_as_string,
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
                physical_resource_id=cr.PhysicalResourceId.of("JobSenderTriggerPhysicalId"),
            ),
            on_update=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": copy_lambda.function_name,
                    "InvocationType": "Event",
                },
                physical_resource_id=cr.PhysicalResourceId.of("JobSenderTriggerPhysicalId"),
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
            targets=[events.CfnRule.TargetProperty(arn=update_lambda.attr_arn, id="UpdateSekoiaCTIGuardDuty")],
        )

        # GuardDuty
        threat_intel_set = gd.CfnThreatIntelSet(
            self,
            "SekoiaCTIThreatIntelSet",
            activate=False,
            detector_id=parameter_DETECTOR.value_as_string,
            format="TXT",
            location=f"s3://{parameter_BUCKET.value_as_string}/sekoia-cti-ipv4.txt",
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
