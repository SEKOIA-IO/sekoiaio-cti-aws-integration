'''
# AWS::M2 Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_m2 as m2
```

<!--BEGIN CFNONLY DISCLAIMER-->

There are no official hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet. Here are some suggestions on how to proceed:

* Search [Construct Hub for M2 construct libraries](https://constructs.dev/search?q=m2)
* Use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, in the same way you would use [the CloudFormation AWS::M2 resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_M2.html) directly.

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::M2](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_M2.html).

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
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnEnvironment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_m2.CfnEnvironment",
):
    '''A CloudFormation ``AWS::M2::Environment``.

    :cloudformationResource: AWS::M2::Environment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_m2 as m2
        
        # storage_configurations: Any
        
        cfn_environment = m2.CfnEnvironment(self, "MyCfnEnvironment",
            engine_type="engineType",
            instance_type="instanceType",
            name="name",
        
            # the properties below are optional
            description="description",
            engine_version="engineVersion",
            high_availability_config=m2.CfnEnvironment.HighAvailabilityConfigProperty(
                desired_capacity=123
            ),
            preferred_maintenance_window="preferredMaintenanceWindow",
            publicly_accessible=False,
            security_group_ids=["securityGroupIds"],
            storage_configurations=[storage_configurations],
            subnet_ids=["subnetIds"],
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        engine_type: builtins.str,
        instance_type: builtins.str,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        high_availability_config: typing.Optional[typing.Union[typing.Union["CfnEnvironment.HighAvailabilityConfigProperty", typing.Dict[str, typing.Any]], _IResolvable_da3f097b]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        publicly_accessible: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        storage_configurations: typing.Optional[typing.Union[typing.Sequence[typing.Any], _IResolvable_da3f097b]] = None,
        subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::M2::Environment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param engine_type: ``AWS::M2::Environment.EngineType``.
        :param instance_type: ``AWS::M2::Environment.InstanceType``.
        :param name: ``AWS::M2::Environment.Name``.
        :param description: ``AWS::M2::Environment.Description``.
        :param engine_version: ``AWS::M2::Environment.EngineVersion``.
        :param high_availability_config: ``AWS::M2::Environment.HighAvailabilityConfig``.
        :param preferred_maintenance_window: ``AWS::M2::Environment.PreferredMaintenanceWindow``.
        :param publicly_accessible: ``AWS::M2::Environment.PubliclyAccessible``.
        :param security_group_ids: ``AWS::M2::Environment.SecurityGroupIds``.
        :param storage_configurations: ``AWS::M2::Environment.StorageConfigurations``.
        :param subnet_ids: ``AWS::M2::Environment.SubnetIds``.
        :param tags: ``AWS::M2::Environment.Tags``.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnEnvironment.__init__)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = CfnEnvironmentProps(
            engine_type=engine_type,
            instance_type=instance_type,
            name=name,
            description=description,
            engine_version=engine_version,
            high_availability_config=high_availability_config,
            preferred_maintenance_window=preferred_maintenance_window,
            publicly_accessible=publicly_accessible,
            security_group_ids=security_group_ids,
            storage_configurations=storage_configurations,
            subnet_ids=subnet_ids,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnEnvironment.inspect)
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
            type_hints = typing.get_type_hints(CfnEnvironment._render_properties)
            check_type(argname="argument props", value=props, expected_type=type_hints["props"])
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property
    @jsii.member(jsii_name="attrEnvironmentArn")
    def attr_environment_arn(self) -> builtins.str:
        '''
        :cloudformationAttribute: EnvironmentArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEnvironmentArn"))

    @builtins.property
    @jsii.member(jsii_name="attrEnvironmentId")
    def attr_environment_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: EnvironmentId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEnvironmentId"))

    @builtins.property
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''``AWS::M2::Environment.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property
    @jsii.member(jsii_name="engineType")
    def engine_type(self) -> builtins.str:
        '''``AWS::M2::Environment.EngineType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-enginetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "engineType"))

    @engine_type.setter
    def engine_type(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "engine_type").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "engineType", value)

    @builtins.property
    @jsii.member(jsii_name="instanceType")
    def instance_type(self) -> builtins.str:
        '''``AWS::M2::Environment.InstanceType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-instancetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceType"))

    @instance_type.setter
    def instance_type(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "instance_type").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "instanceType", value)

    @builtins.property
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''``AWS::M2::Environment.Name``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "name").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "name", value)

    @builtins.property
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''``AWS::M2::Environment.Description``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "description").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "description", value)

    @builtins.property
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''``AWS::M2::Environment.EngineVersion``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-engineversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: typing.Optional[builtins.str]) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "engine_version").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "engineVersion", value)

    @builtins.property
    @jsii.member(jsii_name="highAvailabilityConfig")
    def high_availability_config(
        self,
    ) -> typing.Optional[typing.Union["CfnEnvironment.HighAvailabilityConfigProperty", _IResolvable_da3f097b]]:
        '''``AWS::M2::Environment.HighAvailabilityConfig``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-highavailabilityconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEnvironment.HighAvailabilityConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "highAvailabilityConfig"))

    @high_availability_config.setter
    def high_availability_config(
        self,
        value: typing.Optional[typing.Union["CfnEnvironment.HighAvailabilityConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "high_availability_config").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "highAvailabilityConfig", value)

    @builtins.property
    @jsii.member(jsii_name="preferredMaintenanceWindow")
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''``AWS::M2::Environment.PreferredMaintenanceWindow``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-preferredmaintenancewindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredMaintenanceWindow"))

    @preferred_maintenance_window.setter
    def preferred_maintenance_window(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "preferred_maintenance_window").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "preferredMaintenanceWindow", value)

    @builtins.property
    @jsii.member(jsii_name="publiclyAccessible")
    def publicly_accessible(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::M2::Environment.PubliclyAccessible``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-publiclyaccessible
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "publiclyAccessible"))

    @publicly_accessible.setter
    def publicly_accessible(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "publicly_accessible").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "publiclyAccessible", value)

    @builtins.property
    @jsii.member(jsii_name="securityGroupIds")
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::M2::Environment.SecurityGroupIds``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-securitygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroupIds"))

    @security_group_ids.setter
    def security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "security_group_ids").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "securityGroupIds", value)

    @builtins.property
    @jsii.member(jsii_name="storageConfigurations")
    def storage_configurations(
        self,
    ) -> typing.Optional[typing.Union[typing.List[typing.Any], _IResolvable_da3f097b]]:
        '''``AWS::M2::Environment.StorageConfigurations``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-storageconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[typing.List[typing.Any], _IResolvable_da3f097b]], jsii.get(self, "storageConfigurations"))

    @storage_configurations.setter
    def storage_configurations(
        self,
        value: typing.Optional[typing.Union[typing.List[typing.Any], _IResolvable_da3f097b]],
    ) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "storage_configurations").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "storageConfigurations", value)

    @builtins.property
    @jsii.member(jsii_name="subnetIds")
    def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::M2::Environment.SubnetIds``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-subnetids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "subnetIds"))

    @subnet_ids.setter
    def subnet_ids(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        if __debug__:
            type_hints = typing.get_type_hints(getattr(CfnEnvironment, "subnet_ids").fset)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        jsii.set(self, "subnetIds", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_m2.CfnEnvironment.HighAvailabilityConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"desired_capacity": "desiredCapacity"},
    )
    class HighAvailabilityConfigProperty:
        def __init__(self, *, desired_capacity: jsii.Number) -> None:
            '''
            :param desired_capacity: ``CfnEnvironment.HighAvailabilityConfigProperty.DesiredCapacity``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-m2-environment-highavailabilityconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_m2 as m2
                
                high_availability_config_property = m2.CfnEnvironment.HighAvailabilityConfigProperty(
                    desired_capacity=123
                )
            '''
            if __debug__:
                type_hints = typing.get_type_hints(CfnEnvironment.HighAvailabilityConfigProperty.__init__)
                check_type(argname="argument desired_capacity", value=desired_capacity, expected_type=type_hints["desired_capacity"])
            self._values: typing.Dict[str, typing.Any] = {
                "desired_capacity": desired_capacity,
            }

        @builtins.property
        def desired_capacity(self) -> jsii.Number:
            '''``CfnEnvironment.HighAvailabilityConfigProperty.DesiredCapacity``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-m2-environment-highavailabilityconfig.html#cfn-m2-environment-highavailabilityconfig-desiredcapacity
            '''
            result = self._values.get("desired_capacity")
            assert result is not None, "Required property 'desired_capacity' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HighAvailabilityConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_m2.CfnEnvironmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "engine_type": "engineType",
        "instance_type": "instanceType",
        "name": "name",
        "description": "description",
        "engine_version": "engineVersion",
        "high_availability_config": "highAvailabilityConfig",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "publicly_accessible": "publiclyAccessible",
        "security_group_ids": "securityGroupIds",
        "storage_configurations": "storageConfigurations",
        "subnet_ids": "subnetIds",
        "tags": "tags",
    },
)
class CfnEnvironmentProps:
    def __init__(
        self,
        *,
        engine_type: builtins.str,
        instance_type: builtins.str,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        high_availability_config: typing.Optional[typing.Union[typing.Union[CfnEnvironment.HighAvailabilityConfigProperty, typing.Dict[str, typing.Any]], _IResolvable_da3f097b]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        publicly_accessible: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        storage_configurations: typing.Optional[typing.Union[typing.Sequence[typing.Any], _IResolvable_da3f097b]] = None,
        subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnEnvironment``.

        :param engine_type: ``AWS::M2::Environment.EngineType``.
        :param instance_type: ``AWS::M2::Environment.InstanceType``.
        :param name: ``AWS::M2::Environment.Name``.
        :param description: ``AWS::M2::Environment.Description``.
        :param engine_version: ``AWS::M2::Environment.EngineVersion``.
        :param high_availability_config: ``AWS::M2::Environment.HighAvailabilityConfig``.
        :param preferred_maintenance_window: ``AWS::M2::Environment.PreferredMaintenanceWindow``.
        :param publicly_accessible: ``AWS::M2::Environment.PubliclyAccessible``.
        :param security_group_ids: ``AWS::M2::Environment.SecurityGroupIds``.
        :param storage_configurations: ``AWS::M2::Environment.StorageConfigurations``.
        :param subnet_ids: ``AWS::M2::Environment.SubnetIds``.
        :param tags: ``AWS::M2::Environment.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_m2 as m2
            
            # storage_configurations: Any
            
            cfn_environment_props = m2.CfnEnvironmentProps(
                engine_type="engineType",
                instance_type="instanceType",
                name="name",
            
                # the properties below are optional
                description="description",
                engine_version="engineVersion",
                high_availability_config=m2.CfnEnvironment.HighAvailabilityConfigProperty(
                    desired_capacity=123
                ),
                preferred_maintenance_window="preferredMaintenanceWindow",
                publicly_accessible=False,
                security_group_ids=["securityGroupIds"],
                storage_configurations=[storage_configurations],
                subnet_ids=["subnetIds"],
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        if __debug__:
            type_hints = typing.get_type_hints(CfnEnvironmentProps.__init__)
            check_type(argname="argument engine_type", value=engine_type, expected_type=type_hints["engine_type"])
            check_type(argname="argument instance_type", value=instance_type, expected_type=type_hints["instance_type"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument description", value=description, expected_type=type_hints["description"])
            check_type(argname="argument engine_version", value=engine_version, expected_type=type_hints["engine_version"])
            check_type(argname="argument high_availability_config", value=high_availability_config, expected_type=type_hints["high_availability_config"])
            check_type(argname="argument preferred_maintenance_window", value=preferred_maintenance_window, expected_type=type_hints["preferred_maintenance_window"])
            check_type(argname="argument publicly_accessible", value=publicly_accessible, expected_type=type_hints["publicly_accessible"])
            check_type(argname="argument security_group_ids", value=security_group_ids, expected_type=type_hints["security_group_ids"])
            check_type(argname="argument storage_configurations", value=storage_configurations, expected_type=type_hints["storage_configurations"])
            check_type(argname="argument subnet_ids", value=subnet_ids, expected_type=type_hints["subnet_ids"])
            check_type(argname="argument tags", value=tags, expected_type=type_hints["tags"])
        self._values: typing.Dict[str, typing.Any] = {
            "engine_type": engine_type,
            "instance_type": instance_type,
            "name": name,
        }
        if description is not None:
            self._values["description"] = description
        if engine_version is not None:
            self._values["engine_version"] = engine_version
        if high_availability_config is not None:
            self._values["high_availability_config"] = high_availability_config
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if publicly_accessible is not None:
            self._values["publicly_accessible"] = publicly_accessible
        if security_group_ids is not None:
            self._values["security_group_ids"] = security_group_ids
        if storage_configurations is not None:
            self._values["storage_configurations"] = storage_configurations
        if subnet_ids is not None:
            self._values["subnet_ids"] = subnet_ids
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def engine_type(self) -> builtins.str:
        '''``AWS::M2::Environment.EngineType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-enginetype
        '''
        result = self._values.get("engine_type")
        assert result is not None, "Required property 'engine_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_type(self) -> builtins.str:
        '''``AWS::M2::Environment.InstanceType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-instancetype
        '''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''``AWS::M2::Environment.Name``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''``AWS::M2::Environment.Description``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''``AWS::M2::Environment.EngineVersion``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-engineversion
        '''
        result = self._values.get("engine_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def high_availability_config(
        self,
    ) -> typing.Optional[typing.Union[CfnEnvironment.HighAvailabilityConfigProperty, _IResolvable_da3f097b]]:
        '''``AWS::M2::Environment.HighAvailabilityConfig``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-highavailabilityconfig
        '''
        result = self._values.get("high_availability_config")
        return typing.cast(typing.Optional[typing.Union[CfnEnvironment.HighAvailabilityConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''``AWS::M2::Environment.PreferredMaintenanceWindow``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-preferredmaintenancewindow
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def publicly_accessible(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::M2::Environment.PubliclyAccessible``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-publiclyaccessible
        '''
        result = self._values.get("publicly_accessible")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::M2::Environment.SecurityGroupIds``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-securitygroupids
        '''
        result = self._values.get("security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def storage_configurations(
        self,
    ) -> typing.Optional[typing.Union[typing.List[typing.Any], _IResolvable_da3f097b]]:
        '''``AWS::M2::Environment.StorageConfigurations``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-storageconfigurations
        '''
        result = self._values.get("storage_configurations")
        return typing.cast(typing.Optional[typing.Union[typing.List[typing.Any], _IResolvable_da3f097b]], result)

    @builtins.property
    def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::M2::Environment.SubnetIds``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-subnetids
        '''
        result = self._values.get("subnet_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''``AWS::M2::Environment.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-m2-environment.html#cfn-m2-environment-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEnvironmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnEnvironment",
    "CfnEnvironmentProps",
]

publication.publish()
