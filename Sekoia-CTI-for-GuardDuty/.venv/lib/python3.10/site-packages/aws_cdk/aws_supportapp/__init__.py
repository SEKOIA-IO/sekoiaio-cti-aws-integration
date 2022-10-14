'''
# AWS::SupportApp Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_supportapp as supportapp
```

<!--BEGIN CFNONLY DISCLAIMER-->

There are no official hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet. Here are some suggestions on how to proceed:

* Search [Construct Hub for SupportApp construct libraries](https://constructs.dev/search?q=supportapp)
* Use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, in the same way you would use [the CloudFormation AWS::SupportApp resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_SupportApp.html) directly.

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::SupportApp](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_SupportApp.html).

(Read the [CDK Contributing Guide](https://github.com/aws/aws-cdk/blob/main/CONTRIBUTING.md) and submit an RFC if you are interested in contributing to this construct library.)

<!--END CFNONLY DISCLAIMER-->
'''
import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

from typeguard import check_type

from .._jsii import *

import constructs
from .. import (
    CfnResource as _CfnResource_9df397a6,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnAccountAlias(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_supportapp.CfnAccountAlias",
):
    '''A CloudFormation ``AWS::SupportApp::AccountAlias``.

    :cloudformationResource: AWS::SupportApp::AccountAlias
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-accountalias.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_supportapp as supportapp
        
        cfn_account_alias = supportapp.CfnAccountAlias(self, "MyCfnAccountAlias",
            account_alias="accountAlias"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        account_alias: builtins.str,
    ) -> None:
        '''Create a new ``AWS::SupportApp::AccountAlias``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param account_alias: ``AWS::SupportApp::AccountAlias.AccountAlias``.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnAccountAlias.__init__)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = CfnAccountAliasProps(account_alias=account_alias)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnAccountAlias.inspect)
            check_type(argname="argument inspector", value=inspector, expected_type=type_hints["inspector"])
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnAccountAlias._render_properties)
            check_type(argname="argument props", value=props, expected_type=type_hints["props"])
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property
    @jsii.member(jsii_name="attrAccountAliasResourceId")
    def attr_account_alias_resource_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: AccountAliasResourceId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAccountAliasResourceId"))

    @builtins.property
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property
    @jsii.member(jsii_name="accountAlias")
    def account_alias(self) -> builtins.str:
        '''``AWS::SupportApp::AccountAlias.AccountAlias``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-accountalias.html#cfn-supportapp-accountalias-accountalias
        '''
        return typing.cast(builtins.str, jsii.get(self, "accountAlias"))

    @account_alias.setter
    def account_alias(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnAccountAlias, "account_alias").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "accountAlias", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_supportapp.CfnAccountAliasProps",
    jsii_struct_bases=[],
    name_mapping={"account_alias": "accountAlias"},
)
class CfnAccountAliasProps:
    def __init__(self, *, account_alias: builtins.str) -> None:
        '''Properties for defining a ``CfnAccountAlias``.

        :param account_alias: ``AWS::SupportApp::AccountAlias.AccountAlias``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-accountalias.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_supportapp as supportapp
            
            cfn_account_alias_props = supportapp.CfnAccountAliasProps(
                account_alias="accountAlias"
            )
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnAccountAliasProps.__init__)
            check_type(argname="argument account_alias", value=account_alias, expected_type=type_hints["account_alias"])
        self._values: typing.Dict[str, typing.Any] = {
            "account_alias": account_alias,
        }

    @builtins.property
    def account_alias(self) -> builtins.str:
        '''``AWS::SupportApp::AccountAlias.AccountAlias``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-accountalias.html#cfn-supportapp-accountalias-accountalias
        '''
        result = self._values.get("account_alias")
        assert result is not None, "Required property 'account_alias' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAccountAliasProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSlackChannelConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_supportapp.CfnSlackChannelConfiguration",
):
    '''A CloudFormation ``AWS::SupportApp::SlackChannelConfiguration``.

    :cloudformationResource: AWS::SupportApp::SlackChannelConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_supportapp as supportapp
        
        cfn_slack_channel_configuration = supportapp.CfnSlackChannelConfiguration(self, "MyCfnSlackChannelConfiguration",
            channel_id="channelId",
            channel_role_arn="channelRoleArn",
            notify_on_case_severity="notifyOnCaseSeverity",
            team_id="teamId",
        
            # the properties below are optional
            channel_name="channelName",
            notify_on_add_correspondence_to_case=False,
            notify_on_create_or_reopen_case=False,
            notify_on_resolve_case=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        channel_id: builtins.str,
        channel_role_arn: builtins.str,
        notify_on_case_severity: builtins.str,
        team_id: builtins.str,
        channel_name: typing.Optional[builtins.str] = None,
        notify_on_add_correspondence_to_case: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        notify_on_create_or_reopen_case: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        notify_on_resolve_case: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::SupportApp::SlackChannelConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param channel_id: ``AWS::SupportApp::SlackChannelConfiguration.ChannelId``.
        :param channel_role_arn: ``AWS::SupportApp::SlackChannelConfiguration.ChannelRoleArn``.
        :param notify_on_case_severity: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCaseSeverity``.
        :param team_id: ``AWS::SupportApp::SlackChannelConfiguration.TeamId``.
        :param channel_name: ``AWS::SupportApp::SlackChannelConfiguration.ChannelName``.
        :param notify_on_add_correspondence_to_case: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnAddCorrespondenceToCase``.
        :param notify_on_create_or_reopen_case: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCreateOrReopenCase``.
        :param notify_on_resolve_case: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnResolveCase``.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnSlackChannelConfiguration.__init__)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = CfnSlackChannelConfigurationProps(
            channel_id=channel_id,
            channel_role_arn=channel_role_arn,
            notify_on_case_severity=notify_on_case_severity,
            team_id=team_id,
            channel_name=channel_name,
            notify_on_add_correspondence_to_case=notify_on_add_correspondence_to_case,
            notify_on_create_or_reopen_case=notify_on_create_or_reopen_case,
            notify_on_resolve_case=notify_on_resolve_case,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnSlackChannelConfiguration.inspect)
            check_type(argname="argument inspector", value=inspector, expected_type=type_hints["inspector"])
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnSlackChannelConfiguration._render_properties)
            check_type(argname="argument props", value=props, expected_type=type_hints["props"])
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property
    @jsii.member(jsii_name="channelId")
    def channel_id(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.ChannelId``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-channelid
        '''
        return typing.cast(builtins.str, jsii.get(self, "channelId"))

    @channel_id.setter
    def channel_id(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "channel_id").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "channelId", value)

    @builtins.property
    @jsii.member(jsii_name="channelRoleArn")
    def channel_role_arn(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.ChannelRoleArn``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-channelrolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "channelRoleArn"))

    @channel_role_arn.setter
    def channel_role_arn(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "channel_role_arn").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "channelRoleArn", value)

    @builtins.property
    @jsii.member(jsii_name="notifyOnCaseSeverity")
    def notify_on_case_severity(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCaseSeverity``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyoncaseseverity
        '''
        return typing.cast(builtins.str, jsii.get(self, "notifyOnCaseSeverity"))

    @notify_on_case_severity.setter
    def notify_on_case_severity(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "notify_on_case_severity").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "notifyOnCaseSeverity", value)

    @builtins.property
    @jsii.member(jsii_name="teamId")
    def team_id(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.TeamId``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-teamid
        '''
        return typing.cast(builtins.str, jsii.get(self, "teamId"))

    @team_id.setter
    def team_id(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "team_id").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "teamId", value)

    @builtins.property
    @jsii.member(jsii_name="channelName")
    def channel_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::SupportApp::SlackChannelConfiguration.ChannelName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-channelname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "channelName"))

    @channel_name.setter
    def channel_name(self, value: typing.Optional[builtins.str]) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "channel_name").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "channelName", value)

    @builtins.property
    @jsii.member(jsii_name="notifyOnAddCorrespondenceToCase")
    def notify_on_add_correspondence_to_case(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnAddCorrespondenceToCase``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyonaddcorrespondencetocase
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "notifyOnAddCorrespondenceToCase"))

    @notify_on_add_correspondence_to_case.setter
    def notify_on_add_correspondence_to_case(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "notify_on_add_correspondence_to_case").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "notifyOnAddCorrespondenceToCase", value)

    @builtins.property
    @jsii.member(jsii_name="notifyOnCreateOrReopenCase")
    def notify_on_create_or_reopen_case(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCreateOrReopenCase``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyoncreateorreopencase
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "notifyOnCreateOrReopenCase"))

    @notify_on_create_or_reopen_case.setter
    def notify_on_create_or_reopen_case(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "notify_on_create_or_reopen_case").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "notifyOnCreateOrReopenCase", value)

    @builtins.property
    @jsii.member(jsii_name="notifyOnResolveCase")
    def notify_on_resolve_case(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnResolveCase``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyonresolvecase
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "notifyOnResolveCase"))

    @notify_on_resolve_case.setter
    def notify_on_resolve_case(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnSlackChannelConfiguration, "notify_on_resolve_case").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "notifyOnResolveCase", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_supportapp.CfnSlackChannelConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "channel_id": "channelId",
        "channel_role_arn": "channelRoleArn",
        "notify_on_case_severity": "notifyOnCaseSeverity",
        "team_id": "teamId",
        "channel_name": "channelName",
        "notify_on_add_correspondence_to_case": "notifyOnAddCorrespondenceToCase",
        "notify_on_create_or_reopen_case": "notifyOnCreateOrReopenCase",
        "notify_on_resolve_case": "notifyOnResolveCase",
    },
)
class CfnSlackChannelConfigurationProps:
    def __init__(
        self,
        *,
        channel_id: builtins.str,
        channel_role_arn: builtins.str,
        notify_on_case_severity: builtins.str,
        team_id: builtins.str,
        channel_name: typing.Optional[builtins.str] = None,
        notify_on_add_correspondence_to_case: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        notify_on_create_or_reopen_case: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        notify_on_resolve_case: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSlackChannelConfiguration``.

        :param channel_id: ``AWS::SupportApp::SlackChannelConfiguration.ChannelId``.
        :param channel_role_arn: ``AWS::SupportApp::SlackChannelConfiguration.ChannelRoleArn``.
        :param notify_on_case_severity: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCaseSeverity``.
        :param team_id: ``AWS::SupportApp::SlackChannelConfiguration.TeamId``.
        :param channel_name: ``AWS::SupportApp::SlackChannelConfiguration.ChannelName``.
        :param notify_on_add_correspondence_to_case: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnAddCorrespondenceToCase``.
        :param notify_on_create_or_reopen_case: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCreateOrReopenCase``.
        :param notify_on_resolve_case: ``AWS::SupportApp::SlackChannelConfiguration.NotifyOnResolveCase``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_supportapp as supportapp
            
            cfn_slack_channel_configuration_props = supportapp.CfnSlackChannelConfigurationProps(
                channel_id="channelId",
                channel_role_arn="channelRoleArn",
                notify_on_case_severity="notifyOnCaseSeverity",
                team_id="teamId",
            
                # the properties below are optional
                channel_name="channelName",
                notify_on_add_correspondence_to_case=False,
                notify_on_create_or_reopen_case=False,
                notify_on_resolve_case=False
            )
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnSlackChannelConfigurationProps.__init__)
            check_type(argname="argument channel_id", value=channel_id, expected_type=type_hints["channel_id"])
            check_type(argname="argument channel_role_arn", value=channel_role_arn, expected_type=type_hints["channel_role_arn"])
            check_type(argname="argument notify_on_case_severity", value=notify_on_case_severity, expected_type=type_hints["notify_on_case_severity"])
            check_type(argname="argument team_id", value=team_id, expected_type=type_hints["team_id"])
            check_type(argname="argument channel_name", value=channel_name, expected_type=type_hints["channel_name"])
            check_type(argname="argument notify_on_add_correspondence_to_case", value=notify_on_add_correspondence_to_case, expected_type=type_hints["notify_on_add_correspondence_to_case"])
            check_type(argname="argument notify_on_create_or_reopen_case", value=notify_on_create_or_reopen_case, expected_type=type_hints["notify_on_create_or_reopen_case"])
            check_type(argname="argument notify_on_resolve_case", value=notify_on_resolve_case, expected_type=type_hints["notify_on_resolve_case"])
        self._values: typing.Dict[str, typing.Any] = {
            "channel_id": channel_id,
            "channel_role_arn": channel_role_arn,
            "notify_on_case_severity": notify_on_case_severity,
            "team_id": team_id,
        }
        if channel_name is not None:
            self._values["channel_name"] = channel_name
        if notify_on_add_correspondence_to_case is not None:
            self._values["notify_on_add_correspondence_to_case"] = notify_on_add_correspondence_to_case
        if notify_on_create_or_reopen_case is not None:
            self._values["notify_on_create_or_reopen_case"] = notify_on_create_or_reopen_case
        if notify_on_resolve_case is not None:
            self._values["notify_on_resolve_case"] = notify_on_resolve_case

    @builtins.property
    def channel_id(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.ChannelId``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-channelid
        '''
        result = self._values.get("channel_id")
        assert result is not None, "Required property 'channel_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def channel_role_arn(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.ChannelRoleArn``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-channelrolearn
        '''
        result = self._values.get("channel_role_arn")
        assert result is not None, "Required property 'channel_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def notify_on_case_severity(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCaseSeverity``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyoncaseseverity
        '''
        result = self._values.get("notify_on_case_severity")
        assert result is not None, "Required property 'notify_on_case_severity' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def team_id(self) -> builtins.str:
        '''``AWS::SupportApp::SlackChannelConfiguration.TeamId``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-teamid
        '''
        result = self._values.get("team_id")
        assert result is not None, "Required property 'team_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def channel_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::SupportApp::SlackChannelConfiguration.ChannelName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-channelname
        '''
        result = self._values.get("channel_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notify_on_add_correspondence_to_case(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnAddCorrespondenceToCase``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyonaddcorrespondencetocase
        '''
        result = self._values.get("notify_on_add_correspondence_to_case")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def notify_on_create_or_reopen_case(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnCreateOrReopenCase``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyoncreateorreopencase
        '''
        result = self._values.get("notify_on_create_or_reopen_case")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def notify_on_resolve_case(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::SupportApp::SlackChannelConfiguration.NotifyOnResolveCase``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-supportapp-slackchannelconfiguration.html#cfn-supportapp-slackchannelconfiguration-notifyonresolvecase
        '''
        result = self._values.get("notify_on_resolve_case")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSlackChannelConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnAccountAlias",
    "CfnAccountAliasProps",
    "CfnSlackChannelConfiguration",
    "CfnSlackChannelConfigurationProps",
]

publication.publish()
