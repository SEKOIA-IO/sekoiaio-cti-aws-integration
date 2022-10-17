from aws_cdk import (
    Stack,
    Duration,
    aws_lambda as lambda_,
    aws_events as events,
    aws_iam as iam,
    aws_s3 as s3,
    aws_networkfirewall as netfw,
    custom_resources as cr,
)
from constructs import Construct
import aws_cdk as cdk


class SekoiaCTINetworkFirewallStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Parameters
        parameter_APIKEY = cdk.CfnParameter(
            self,
            "APIKEYParameter",
            description="Please enter the SEKOIA.IO API KEY. It is provided by SEKOIA.IO at subscription.",
        )

        # S3
        my_bucket = s3.CfnBucket(
            self,
            "SEKOIA_CTI_Bucket",
            bucket_name="sekoia-cti-network-firewall",
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
            "CopySekoiaLambdaNetworkFirewallRole",
            role_name="CopySekoiaLambdaNetworkFirewallRole",
            description="This role is specific to lambda function named CopySekoiaLambdaNetworkFirewall. It allows to write logs, to RW on a specific bucket.",
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
            "CopySekoiaLambdaNetworkFirewallPolicy",
            policy_name="CopySekoiaLambdaNetworkFirewallPolicy",
            roles=["CopySekoiaLambdaNetworkFirewallRole"],
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
            "UpdateSekoiaCTINetworkFirewallRole",
            role_name="UpdateSekoiaCTINetworkFirewallRole",
            description="This role is specific to lambda function named UpdateSekoiaCTIForNetworkFirewall. It allows to write logs, to update Firewall Network Rule Groups.",
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

        lambda_policy = iam.CfnPolicy(
            self,
            "UpdateSekoiaCTINetworkFirewallPolicy",
            policy_name="UpdateSekoiaCTINetworkFirewallPolicy",
            roles=["UpdateSekoiaCTINetworkFirewallRole"],
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
                        "Action": [
                            "network-firewall:DescribeRuleGroup",
                            "network-firewall:UpdateRuleGroup",
                        ],
                        "Resource": "arn:aws:network-firewall:"
                        + self.region
                        + ":"
                        + self.account
                        + ":stateful-rulegroup/*",
                    },
                ],
            },
        )
        lambda_policy.add_depends_on(update_lambda_role)

        # Network-Firewall Rule Group
        rule_group = netfw.CfnRuleGroup(
            self,
            "SekoiaNetworkFirewallRuleGroup",
            capacity=30000,
            rule_group_name="SekoiaCTIDomainNameRuleGroup",
            type="STATEFUL",
            rule_group=netfw.CfnRuleGroup.RuleGroupProperty(
                rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
                    rules_source_list=netfw.CfnRuleGroup.RulesSourceListProperty(
                        generated_rules_type="DENYLIST",
                        targets=["example.com"],
                        target_types=["TLS_SNI", "HTTP_HOST"],
                    )
                )
            ),
        )

        # Network-Firewall Firewall Policy
        firewall_policy_property = netfw.CfnFirewallPolicy.FirewallPolicyProperty(
            stateless_default_actions=["aws:forward_to_sfe"],
            stateless_fragment_default_actions=["aws:forward_to_sfe"],
            stateful_rule_group_references=[
                netfw.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                    resource_arn=rule_group.attr_rule_group_arn
                )
            ],
        )

        firewall_policy = netfw.CfnFirewallPolicy(
            self,
            "SekoiaNetworkFirewallPolicy",
            firewall_policy_name="SekoiaNetworkFirewallPolicy",
            firewall_policy=firewall_policy_property,
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
    r = requests.get("https://raw.githubusercontent.com/maxime-el-haddari/testing-lambda/main/sekoia-update-cti-network-firewall.zip")
    with open("/tmp/sekoia-update-cti-network-firewall.zip", "wb") as f:
        f.write(r.content)
    s3_client = boto3.client("s3")
    s3_client.upload_file("/tmp/sekoia-update-cti-network-firewall.zip", BUCKET_NAME, "sekoia-update-cti-network-firewall.zip")
            """
            ),
            role=copy_lambda_role.attr_arn,
            runtime="python3.7",
            handler="index.handler",
            package_type="Zip",
            function_name="CopySekoiaLambdaNetworkFirewall",
            environment=lambda_.CfnFunction.EnvironmentProperty(
                variables={
                    "BUCKET_NAME": my_bucket.bucket_name,
                }
            ),
            timeout=10,
        )
        update_lambda = lambda_.CfnFunction(
            self,
            "UpdateSEKOIACTINetworkFirewall",
            code=lambda_.CfnFunction.CodeProperty(
                s3_bucket=my_bucket.bucket_name,
                s3_key="sekoia-update-cti-network-firewall.zip",
            ),
            role=update_lambda_role.attr_arn,
            runtime="python3.7",
            handler="app.handler",
            package_type="Zip",
            function_name="UpdateSekoiaCTINetworkFirewall",
            environment=lambda_.CfnFunction.EnvironmentProperty(
                variables={
                    "API_KEY": parameter_APIKEY.value_as_string,
                }
            ),
            timeout=30,
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
            function_name="CopyLambdaNetworkFirewallEvent",
        )
        update_lambda.node.add_dependency(copy_trigger)

        # BridgeEvents
        event_rule = events.CfnRule(
            self,
            "SEKOIALambdaScheduler",
            description="Schedule rule to trigger Lambda UpdateSekoiaCTINetworkFirewall",
            name="SEKOIALambdaSchedulerNetworkFirewall",
            state="ENABLED",
            schedule_expression="rate(10 minutes)",
            targets=[
                events.CfnRule.TargetProperty(
                    arn=update_lambda.attr_arn, id="UpdateSekoiaCTINetworkFirewall"
                )
            ],
        )

        # Permissions
        lambda_permission = lambda_.CfnPermission(
            self,
            "LambdaPermissionInvoke",
            action="lambda:InvokeFunction",
            principal="events.amazonaws.com",
            function_name="UpdateSekoiaCTINetworkFirewall",
            source_arn=event_rule.attr_arn,
        )
