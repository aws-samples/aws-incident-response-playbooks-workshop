"""
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Building Incident Response Playbooks for AWS

## Workshop stack
"""
from aws_cdk import (
    core,
    aws_s3,
    aws_athena,
    aws_cloudtrail,
    aws_guardduty,
    aws_glue,
    aws_ec2,
    aws_route53resolver,
    aws_iam,
)


class WorkshopStack(core.Stack):
    def __init__(
            self, scope: core.Construct, construct_id: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        logging_bucket = aws_s3.Bucket(
            self,
            "BucketLogs",
            bucket_name=core.PhysicalName.GENERATE_IF_NEEDED,
            block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL,
        )
        logging_bucket.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="AllowAWSServiceGetBucketAcl",
                effect=aws_iam.Effect.ALLOW,
                principals=[aws_iam.ServicePrincipal(service="cloudtrail.amazonaws.com"),
                            aws_iam.ServicePrincipal(service="delivery.logs.amazonaws.com")],
                actions=["s3:GetBucketAcl"],
                resources=[logging_bucket.bucket_arn],
            )
        )
        logging_bucket.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="AllowAWSServicePutObject",
                effect=aws_iam.Effect.ALLOW,
                principals=[aws_iam.ServicePrincipal(service="cloudtrail.amazonaws.com"),
                            aws_iam.ServicePrincipal(service="delivery.logs.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[logging_bucket.bucket_arn + "/*"],
                conditions={
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                },
            )
        )
        athena_bucket = aws_s3.Bucket(
            self,
            "BucketAthena",
            bucket_name=core.PhysicalName.GENERATE_IF_NEEDED,
            block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL,
        )
        cloutrail_trail = aws_cloudtrail.Trail(
            self,
            "Trail",
            is_multi_region_trail=True,
            enable_file_validation=True,
            bucket=logging_bucket,
            trail_name="IRWorkshopTrail",
        )
        cloutrail_trail.log_all_s3_data_events()
        guardduty_detector = aws_guardduty.CfnDetector(
            self,
            "IRWorkshopGuardDutyDetector",
            enable=True,
        )
        vpc_subnets = [aws_ec2.SubnetConfiguration(
            subnet_type=aws_ec2.SubnetType.PUBLIC,
            name="Public",
            cidr_mask=24
        ),
            aws_ec2.SubnetConfiguration(
                subnet_type=aws_ec2.SubnetType.PRIVATE,
                name="Private",
                cidr_mask=24
            )]
        vpc = aws_ec2.Vpc(
            self,
            "VPC",
            cidr="192.168.0.0/16",
            max_azs=2,
            subnet_configuration=vpc_subnets,
            nat_gateways=1,
        )
        amzn_linux = aws_ec2.MachineImage.latest_amazon_linux(
            generation=aws_ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            edition=aws_ec2.AmazonLinuxEdition.STANDARD,
            virtualization=aws_ec2.AmazonLinuxVirt.HVM,
            storage=aws_ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
        )
        security_group = aws_ec2.SecurityGroup(
            self,
            "SecurityGroup",
            vpc=vpc,
            description="Allow all outbound and allow SSH from internet",
        )
        security_group.add_ingress_rule(
            connection=aws_ec2.Port.tcp(22),
            description="allow SSH TCP/22 within VPC CIDR",
            peer=aws_ec2.Peer.ipv4("192.168.0.0/16"),
        )
        just_an_instance = aws_ec2.Instance(
            self,
            "JustAnInstance",
            allow_all_outbound=True,
            instance_name="just_an_instance",
            instance_type=aws_ec2.InstanceType("t3.nano"),
            machine_image=amzn_linux,
            vpc=vpc,
            vpc_subnets=vpc.public_subnets[1],
            security_group=security_group,
        )
        vpc_flow_log = aws_ec2.CfnFlowLog(
            self,
            "VPCFlowLog",
            resource_id=vpc.vpc_id,
            resource_type="VPC",
            traffic_type="ALL",
            log_destination_type="s3",
            log_destination=logging_bucket.bucket_arn,
            log_format="".join(["${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ",
                                "${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ",
                                "${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ",
                                "${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ",
                                "${pkt-dst-aws-service} ${flow-direction} ${traffic-path}"]),
            max_aggregation_interval=60,
        )
        dns_logs = aws_route53resolver.CfnResolverQueryLoggingConfig(
            self,
            "DNSLogs",
            destination_arn=logging_bucket.bucket_arn,
            name="DNS Logs for IR Workshop",
        )
        dns_logs_association = aws_route53resolver.CfnResolverQueryLoggingConfigAssociation(
            self,
            "DNSLogsAssociation",
            resolver_query_log_config_id=dns_logs.attr_id,
            resource_id=vpc.vpc_id,
        )
        dns_logs_association.add_depends_on(dns_logs)
        athena_workgroup_output_location = "".join(["s3://",
                                                    athena_bucket.bucket_name,
                                                    "/"])
        athena_workgroup = aws_athena.CfnWorkGroup(
            self,
            "AthenaWorkGroup",
            name="IRWorkshopAthenaWorkGroup",
            state="ENABLED",
            recursive_delete_option=True,
            work_group_configuration=aws_athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                enforce_work_group_configuration=True,
                result_configuration=aws_athena.CfnWorkGroup.ResultConfigurationProperty(
                    encryption_configuration=aws_athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_S3",
                    ),
                    output_location=athena_workgroup_output_location,
                ),
                requester_pays_enabled=False,
                publish_cloud_watch_metrics_enabled=False,
                engine_version=aws_athena.CfnWorkGroup.EngineVersionProperty(
                    selected_engine_version="Athena engine version 2",
                )
            )
        )
        core.CfnOutput(
            self,
            "AthenaWorkgroupQueryOutputLocation",
            description="Athena Workgroup queries output location",
            value=athena_workgroup_output_location,
        )
        core.CfnOutput(
            self,
            "AthenaWorkgroupName",
            description="Athena Workgroup for workshop use",
            value=athena_workgroup.name,
        )
        glue_database = aws_glue.CfnDatabase(
            self,
            "IRWorkshopGlueDatabase",
            catalog_id=core.Aws.ACCOUNT_ID,
            database_input=aws_glue.CfnDatabase.DatabaseInputProperty(
                name="irworkshopgluedatabase",
            ),
        )
        CfnParamCloudTrailProjectionEventStartDate = core.CfnParameter(
            self,
            "ParamCloudTrailProjectionEventStartDate",
            type="String",
            default="2021/06/14",
            description="Athena CloudTrail Table Projection Partition Start Date",
        )
        RegionPartitionValues = "".join(["us-east-2,us-east-1,us-west-1,us-west-2,af-south-1,ap-east-1,",
                                        "ap-south-1,ap-northeast-3,ap-northeast-2,ap-southeast-1,ap-southeast-2,",
                                        "ap-northeast-1,ca-central-1,cn-north-1,cn-northwest-1,eu-central-1,",
                                        "eu-west-1,eu-west-2,eu-south-1,eu-west-3,eu-north-1,me-south-1,sa-east-1"])
        CloudTrailProjectionDateRange = CfnParamCloudTrailProjectionEventStartDate.value_as_string + ", NOW"
        CloudTrailSource = "".join(["s3://",
                                    logging_bucket.bucket_name,
                                    "/AWSLogs/",
                                    "${account_partition}/CloudTrail/${region_partition}/${date_partition}"])
        glue_table_cloudtrail_parameters = {
            "classification": "json",
            "EXTERNAL": "true",
            "projection.enabled": "true",
            "projection.date_partition.type": "date",
            "projection.date_partition.range": CloudTrailProjectionDateRange,
            "projection.date_partition.format": "yyyy/MM/dd",
            "projection.date_partition.interval": "1",
            "projection.date_partition.interval.unit": "DAYS",
            "projection.region_partition.type": "enum",
            "projection.region_partition.values": RegionPartitionValues,
            "projection.account_partition.type": "enum",
            "projection.account_partition.values": core.Aws.ACCOUNT_ID,
            "storage.location.template": CloudTrailSource,
        }
        glue_table_cloudtrail_partition_keys = [
            {"name": "date_partition", "type": "string"},
            {"name": "region_partition", "type": "string"},
            {"name": "account_partition", "type": "string"},

        ]
        glue_table_cloudtrail_columns = [
            {"name": "eventversion", "type": "string"},
            {"name": "useridentity", "type": "struct<type:string,principalid:string,arn:string,accountid:string,"
                                             "invokedby:string,accesskeyid:string,userName:string,"
                                             "sessioncontext:struct<attributes:struct<mfaauthenticated:string,"
                                             "creationdate:string>,sessionissuer:struct<type:string,"
                                             "principalId:string,arn:string,accountId:string,userName:string>>>"},
            {"name": "eventtime", "type": "string"},
            {"name": "eventsource", "type": "string"},
            {"name": "eventname", "type": "string"},
            {"name": "awsregion", "type": "string"},
            {"name": "sourceipaddress", "type": "string"},
            {"name": "useragent", "type": "string"},
            {"name": "errorcode", "type": "string"},
            {"name": "errormessage", "type": "string"},
            {"name": "requestparameters", "type": "string"},
            {"name": "responseelements", "type": "string"},
            {"name": "additionaleventdata", "type": "string"},
            {"name": "eventid", "type": "string"},
            {"name": "resources", "type": "array<struct<ARN:string,accountId:string,type:string>>"},
            {"name": "eventtype", "type": "string"},
            {"name": "apiversion", "type": "string"},
            {"name": "readonly", "type": "string"},
            {"name": "recipientaccountid", "type": "string"},
            {"name": "serviceeventdetails", "type": "string"},
            {"name": "sharedeventid", "type": "string"},
            {"name": "vpcendpointid", "type": "string"},
        ]
        logs_location = "".join(["s3://",
                                 logging_bucket.bucket_name,
                                 "/AWSLogs/"])
        core.CfnOutput(
            self,
            "S3BucketLocationWithLogs",
            description="S3 Bucket location containing CloudTrail, VPC Flow, and DNS logs for workshop use",
            value=logs_location,
        )
        glue_table_cloudtrail = aws_glue.CfnTable(
            self,
            "IRWorkshopGlueTableCloudTrail",
            catalog_id=core.Aws.ACCOUNT_ID,
            database_name="irworkshopgluedatabase",
            table_input=aws_glue.CfnTable.TableInputProperty(
                name="irworkshopgluetablecloudtrail",
                table_type="EXTERNAL_TABLE",
                parameters=glue_table_cloudtrail_parameters,
                partition_keys=glue_table_cloudtrail_partition_keys,
                storage_descriptor=aws_glue.CfnTable.StorageDescriptorProperty(
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    columns=glue_table_cloudtrail_columns,
                    input_format="com.amazon.emr.cloudtrail.CloudTrailInputFormat",
                    location=logs_location,
                    serde_info=aws_glue.CfnTable.SerdeInfoProperty(
                        parameters={"serialization.format": "1"},
                        serialization_library="com.amazon.emr.hive.serde.CloudTrailSerde",
                    ),
                )
            ),
        )

        CfnParamVPCFlowProjectionEventStartDate = core.CfnParameter(
            self,
            "ParamVPCFlowProjectionEventStartDate",
            type="String",
            default="2021/06/14",
            description="Athena VPC Flow Table Projection Partition Start Date",
        )
        VPCFlowProjectionDateRange = CfnParamVPCFlowProjectionEventStartDate.value_as_string + ", NOW"
        VPCFlowSource = "".join(["s3://",
                                 logging_bucket.bucket_name,
                                 "/AWSLogs/",
                                 "${account_partition}/vpcflowlogs/${region_partition}/${date_partition}"])
        glue_table_vpcflow_parameters = {
            "classification": "csv",
            "EXTERNAL": "true",
            "projection.enabled": "true",
            "projection.date_partition.type": "date",
            "projection.date_partition.range": VPCFlowProjectionDateRange,
            "projection.date_partition.format": "yyyy/MM/dd",
            "projection.date_partition.interval": "1",
            "projection.date_partition.interval.unit": "DAYS",
            "projection.region_partition.type": "enum",
            "projection.region_partition.values": RegionPartitionValues,
            "projection.account_partition.type": "enum",
            "projection.account_partition.values": core.Aws.ACCOUNT_ID,
            "storage.location.template": VPCFlowSource,
        }
        glue_table_vpcflow_partition_keys = [
            {"name": "date_partition", "type": "string"},
            {"name": "region_partition", "type": "string"},
            {"name": "account_partition", "type": "string"},

        ]
        glue_table_vpcflow_columns = [
            {"name": "version", "type": "int"},
            {"name": "account", "type": "string"},
            {"name": "interfaceid", "type": "string"},
            {"name": "sourceaddress", "type": "string"},
            {"name": "destinationaddress", "type": "string"},
            {"name": "sourceport", "type": "int"},
            {"name": "destinationport", "type": "int"},
            {"name": "protocol", "type": "int"},
            {"name": "numpackets", "type": "int"},
            {"name": "numbytes", "type": "bigint"},
            {"name": "starttime", "type": "int"},
            {"name": "endtime", "type": "int"},
            {"name": "action", "type": "string"},
            {"name": "logstatus", "type": "string"},
            {"name": "vpcid", "type": "string"},
            {"name": "subnetid", "type": "string"},
            {"name": "instanceid", "type": "string"},
            {"name": "tcpflags", "type": "smallint"},
            {"name": "type", "type": "string"},
            {"name": "pktsrcaddr", "type": "string"},
            {"name": "pktdstaddr", "type": "string"},
            {"name": "region", "type": "string"},
            {"name": "azid", "type": "string"},
            {"name": "sublocationtype", "type": "string"},
            {"name": "sublocationid", "type": "string"},
            {"name": "pkt_src_aws_service", "type": "string"},
            {"name": "pkt_dst_aws_service", "type": "string"},
            {"name": "flow_direction", "type": "string"},
            {"name": "traffic_path", "type": "string"},
        ]
        logs_location = "".join(["s3://",
                                 logging_bucket.bucket_name,
                                 "/AWSLogs/"])
        glue_table_vpcflow = aws_glue.CfnTable(
            self,
            "IRWorkshopGlueTableVPCFlow",
            catalog_id=core.Aws.ACCOUNT_ID,
            database_name="irworkshopgluedatabase",
            table_input=aws_glue.CfnTable.TableInputProperty(
                name="irworkshopgluetablevpcflow",
                table_type="EXTERNAL_TABLE",
                parameters=glue_table_vpcflow_parameters,
                partition_keys=glue_table_vpcflow_partition_keys,
                storage_descriptor=aws_glue.CfnTable.StorageDescriptorProperty(
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    columns=glue_table_vpcflow_columns,
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    location=logs_location,
                    serde_info=aws_glue.CfnTable.SerdeInfoProperty(
                        parameters={"serialization.format": "",
                                    "field.delim": " "},
                        serialization_library="org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    ),
                )
            ),
        )
        CfnParamDNSProjectionEventStartDate = core.CfnParameter(
            self,
            "ParamDNSProjectionEventStartDate",
            type="String",
            default="2021/06/14",
            description="Athena DNS Table Projection Partition Start Date",
        )
        DNSProjectionDateRange = CfnParamDNSProjectionEventStartDate.value_as_string + ", NOW"
        DNSSource = "".join(["s3://",
                             logging_bucket.bucket_name,
                             "/AWSLogs/",
                             "${account_partition}/vpcdnsquerylogs/${vpc_partition}/${date_partition}"])
        glue_table_dns_parameters = {
            "classification": "csv",
            "EXTERNAL": "true",
            "projection.enabled": "true",
            "projection.date_partition.type": "date",
            "projection.date_partition.range": DNSProjectionDateRange,
            "projection.date_partition.format": "yyyy/MM/dd",
            "projection.date_partition.interval": "1",
            "projection.date_partition.interval.unit": "DAYS",
            "projection.vpc_partition.type": "enum",
            "projection.vpc_partition.values": vpc.vpc_id,
            "projection.account_partition.type": "enum",
            "projection.account_partition.values": core.Aws.ACCOUNT_ID,
            "storage.location.template": DNSSource,
        }
        glue_table_dns_partition_keys = [
            {"name": "date_partition", "type": "string"},
            {"name": "vpc_partition", "type": "string"},
            {"name": "account_partition", "type": "string"},

        ]
        glue_table_dns_columns = [
            {"name": "version", "type": "float"},
            {"name": "account_id", "type": "string"},
            {"name": "region", "type": "string"},
            {"name": "vpc_id", "type": "string"},
            {"name": "query_timestamp", "type": "string"},
            {"name": "query_name", "type": "string"},
            {"name": "query_type", "type": "string"},
            {"name": "query_class", "type": "string"},
            {"name": "rcode", "type": "string"},
            {"name": "answers", "type": "array<string>"},
            {"name": "srcaddr", "type": "string"},
            {"name": "srcport", "type": "int"},
            {"name": "transport", "type": "string"},
            {"name": "srcids", "type": "string"},
        ]
        glue_table_dns = aws_glue.CfnTable(
            self,
            "IRWorkshopGlueTableDNS",
            catalog_id=core.Aws.ACCOUNT_ID,
            database_name="irworkshopgluedatabase",
            table_input=aws_glue.CfnTable.TableInputProperty(
                name="irworkshopgluetabledns",
                table_type="EXTERNAL_TABLE",
                parameters=glue_table_dns_parameters,
                partition_keys=glue_table_dns_partition_keys,
                storage_descriptor=aws_glue.CfnTable.StorageDescriptorProperty(
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    columns=glue_table_dns_columns,
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    location=logs_location,
                    serde_info=aws_glue.CfnTable.SerdeInfoProperty(
                        parameters={"serialization.format": ""},
                        serialization_library="org.openx.data.jsonserde.JsonSerDe",
                    ),
                )
            ),
        )

        CfnParamBaseIAMRole = core.CfnParameter(
            self,
            "ParamBaseIAMRole",
            type="String",
            default="TeamRole",
            description="Existing IAM Role to be used to assume workshop IAM Roles",
        )

        security_analyst_role_policy = aws_iam.ManagedPolicy(
            self,
            "SecurityAnalystRolePolicy",
            statements=[
                aws_iam.PolicyStatement(
                    sid="SecurityGuardDutyReadOnlyAccess",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["guardduty:ListMembers",
                             "guardduty:GetMembers",
                             "guardduty:ListInvitations",
                             "guardduty:ListDetectors",
                             "guardduty:GetDetector",
                             "guardduty:ListFindings",
                             "guardduty:GetFindings",
                             "guardduty:ListIPSets",
                             "guardduty:GetIPSet",
                             "guardduty:ListThreatIntelSets",
                             "guardduty:GetThreatIntelSet",
                             "guardduty:GetMasterAccount",
                             "guardduty:GetInvitationsCount",
                             "guardduty:GetFindingsStatistics"],
                    resources=["*"]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityNamedQueryFullAccess",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["athena:BatchGetNamedQuery",
                             "athena:CreateNamedQuery",
                             "athena:DeleteNamedQuery",
                             "athena:GetNamedQuery",
                             "athena:ListNamedQueries"],
                    resources=["".join(["arn:aws:athena:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":workgroup/", athena_workgroup.name])]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityWorkgroupReadOnly",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["athena:GetWorkGroup",
                             "athena:ListWorkGroups",
                             "athena:BatchGetQueryExecution",
                             "athena:GetQueryExecution",
                             "athena:GetQueryResults",
                             "athena:GetQueryResultsStream",
                             "athena:ListQueryExecutions",
                             "athena:ListTagsForResource",
                             "athena:StartQueryExecution",
                             "athena:StopQueryExecution"],
                    resources=["".join(["arn:aws:athena:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":workgroup/", athena_workgroup.name])]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityWorkgroupListAll",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["athena:ListWorkGroups"],
                    resources=["*"]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityAthenaDataCatalogReadOnly",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["athena:GetDataCatalog",
                             "athena:ListDataCatalogs",
                             "athena:GetDatabase",
                             "athena:ListDatabases",
                             "athena:GetTableMetadata",
                             "athena:ListTableMetadata"],
                    resources=["".join(["arn:aws:athena:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":datacatalog/", athena_workgroup.name])]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityGlueDatabaseReadOnly",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["glue:GetDatabase",
                             "glue:GetDatabases"],
                    resources=["".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":database/", glue_database.database_input.name]),
                               "".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":catalog"])
                               ]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityGlueTableReadOnly",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["glue:GetTable",
                             "glue:GetTables"],
                    resources=["".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":table/", glue_database.database_input.name, "/*"]),
                               "".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":database/", glue_database.database_input.name]),
                               "".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":catalog"])
                               ]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityGluePartitionReadOnly",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["glue:BatchGetPartition",
                             "glue:GetPartition",
                             "glue:GetPartitions"],
                    resources=["".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":database/", athena_workgroup.name])]
                ),
                aws_iam.PolicyStatement(
                    sid="AthenaOutputBucketReadWrite",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:AbortMultipartUpload",
                             "s3:GetBucketLocation",
                             "s3:GetObject",
                             "s3:ListBucket",
                             "s3:ListBucketMultipartUploads",
                             "s3:ListMultipartUploadParts",
                             "s3:PutObject"],
                    resources=[athena_bucket.bucket_arn,
                               athena_bucket.bucket_arn + "/*"]
                ),
                aws_iam.PolicyStatement(
                    sid="LogSourceBucketReadOnly",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:GetObject",
                             "s3:ListBucket"],
                    resources=[logging_bucket.bucket_arn,
                               logging_bucket.bucket_arn + "/*"]
                ),
                aws_iam.PolicyStatement(
                    sid="ListLogAndOutputBuckets",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:GetBucketLocation",
                             "s3:ListBucket"],
                    resources=[logging_bucket.bucket_arn,
                               athena_bucket.bucket_arn]
                ),
            ]
        )

        security_analyst_role = aws_iam.Role(
            self,
            "SecurityAnalystRole",
            role_name="SecurityAnalystRole",
            managed_policies=[security_analyst_role_policy],
            assumed_by=aws_iam.AccountPrincipal(
                account_id=core.Aws.ACCOUNT_ID
            ).with_conditions(
                {"StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::" + core.Aws.ACCOUNT_ID + ":role/" + CfnParamBaseIAMRole.value_as_string
                    ]
                }
                }
            )
        )
        core.CfnOutput(
            self,
            "SecurityAnalystRoleARNforAthena",
            description="Role ARN to be assumed by security analyst for Athena use",
            value=security_analyst_role.role_arn,
        )

        athena_admin_role_policy = aws_iam.ManagedPolicy(
            self,
            "AthenaAdminRolePolicy",
            statements=[
                aws_iam.PolicyStatement(
                    sid="SecurityNamedQueryFullAccess",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["athena:BatchGetNamedQuery",
                             "athena:CreateNamedQuery",
                             "athena:DeleteNamedQuery",
                             "athena:GetNamedQuery",
                             "athena:ListNamedQueries"],
                    resources=["".join(["arn:aws:athena:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":workgroup/*"])
                               ]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityWorkgroupFullAccess",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["athena:CreateWorkGroup",
                             "athena:DeleteWorkGroup",
                             "athena:GetWorkGroup",
                             "athena:ListWorkGroups",
                             "athena:UpdateWorkGroup",
                             "athena:BatchGetQueryExecution",
                             "athena:GetQueryExecution",
                             "athena:GetQueryResults",
                             "athena:GetQueryResultsStream",
                             "athena:ListQueryExecutions",
                             "athena:ListTagsForResource",
                             "athena:StartQueryExecution",
                             "athena:StopQueryExecution"],
                    resources=["".join(["arn:aws:athena:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":workgroup/*"])
                               ]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityAthenaDataCatalogFullAccess",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["athena:CreateDataCatalog",
                             "athena:DeleteDataCatalog",
                             "athena:GetDataCatalog",
                             "athena:ListDataCatalogs",
                             "athena:UpdateDataCatalog",
                             "athena:GetDatabase",
                             "athena:ListDatabases",
                             "athena:GetTableMetadata",
                             "athena:ListTableMetadata"],
                    resources=["".join(["arn:aws:athena:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":datacatalog/*"])
                               ]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityGlueDatabaseFullAccess",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["glue:CreateDatabase",
                             "glue:DeleteDatabase",
                             "glue:GetDatabase",
                             "glue:GetDatabases",
                             "glue:UpdateDatabase"],
                    resources=["".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":database/*"]),
                               "".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":catalog"])
                               ]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityGlueTableFullAccess",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["glue:BatchDeleteTable",
                             "glue:CreateTable",
                             "glue:DeleteTable",
                             "glue:GetTables",
                             "glue:GetTable",
                             "glue:UpdateTable"],
                    resources=["".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":table/*"]),
                               "".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":database/*"]),
                               "".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":catalog"])
                               ]
                ),
                aws_iam.PolicyStatement(
                    sid="SecurityGluePartitionReadWrite",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["glue:BatchCreatePartition",
                             "glue:BatchDeletePartition",
                             "glue:BatchGetPartition",
                             "glue:CreatePartition",
                             "glue:DeletePartition",
                             "glue:GetPartitions",
                             "glue:BatchGetPartition",
                             "glue:UpdatePartition"],
                    resources=["".join(["arn:aws:glue:", core.Aws.REGION, ":", core.Aws.ACCOUNT_ID,
                                        ":database/*"])]
                ),
                aws_iam.PolicyStatement(
                    sid="AthenaOutputBucketReadWrite",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:AbortMultipartUpload",
                             "s3:GetBucketLocation",
                             "s3:GetObject",
                             "s3:ListBucket",
                             "s3:ListBucketMultipartUploads",
                             "s3:ListMultipartUploadParts",
                             "s3:PutObject"],
                    resources=[athena_bucket.bucket_arn,
                               athena_bucket.bucket_arn + "/*"]
                ),
                aws_iam.PolicyStatement(
                    sid="LogSourceBucketReadOnly",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:GetObject",
                             "s3:ListBucket"],
                    resources=[logging_bucket.bucket_arn,
                               logging_bucket.bucket_arn + "/*"]
                ),
                aws_iam.PolicyStatement(
                    sid="ListLogAndOutputBuckets",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:GetBucketLocation",
                             "s3:ListBucket",
                             "s3:ListAllMyBuckets"],
                    resources=[logging_bucket.bucket_arn,
                               athena_bucket.bucket_arn]
                ),
            ]
        )

        athena_admin_role = aws_iam.Role(
            self,
            "AthenaAdminRole",
            role_name="SecurityAdminRole",
            managed_policies=[athena_admin_role_policy],
            assumed_by=aws_iam.AccountPrincipal(
                account_id=core.Aws.ACCOUNT_ID
            ).with_conditions(
                {"StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::" + core.Aws.ACCOUNT_ID + ":role/" + CfnParamBaseIAMRole.value_as_string
                    ]
                }
                }
            )
        )

        core.CfnOutput(
            self,
            "AthenaAdminRoleARN",
            description="Role ARN to be assumed by Athena administrator",
            value=athena_admin_role.role_arn,
        )

        security_break_glass_role = aws_iam.Role(
            self,
            "SecurityBreakGlassRole",
            role_name="SecurityBreakGlassRole",
            managed_policies=[aws_iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess")],
            assumed_by=aws_iam.AccountPrincipal(
                account_id=core.Aws.ACCOUNT_ID
            ).with_conditions(
                {"StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::" + core.Aws.ACCOUNT_ID + ":role/" + CfnParamBaseIAMRole.value_as_string
                    ]
                }
                }
            )
        )

        core.CfnOutput(
            self,
            "SecurityBreakGlassRoleArn",
            description="Role ARN for Break Glass purposes during incidents",
            value=security_break_glass_role.role_arn,
        )

        security_deploy_role_policy = aws_iam.ManagedPolicy(
            self,
            "SecurityDeployRolePolicy",
            statements=[
                aws_iam.PolicyStatement(
                    sid="StackPermissions",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["cloudformation:CreateStack",
                             "cloudformation:DescribeStacks",
                             "cloudformation:DescribeStackEvents",
                             "cloudformation:DescribeStackResources",
                             "cloudformation:GetTemplate",
                             "cloudformation:GetTemplateSummary",
                             "cloudformation:ValidateTemplate",
                             "cloudformation:CreateUploadBucket"],
                    resources=["*"]
                ),
                aws_iam.PolicyStatement(
                    sid="S3Permissions",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:PutObject",
                             "s3:ListBucket",
                             "s3:GetObject",
                             "s3:CreateBucket"],
                    resources=["*"]
                ),
                aws_iam.PolicyStatement(
                    sid="IAMPermissions",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["iam:CreateUser",
                             "iam:CreatePolicy",
                             "iam:CreateAccessKey",
                             "iam:GetUser",
                             "iam:GetPolicy"],
                    resources=["*"]
                ),
            ]
        )

        security_deploy_role = aws_iam.Role(
            self,
            "SecurityDeployRole",
            role_name="SecurityDeployRole",
            managed_policies=[security_deploy_role_policy],
            assumed_by=aws_iam.AccountPrincipal(
                account_id=core.Aws.ACCOUNT_ID
            ).with_conditions(
                {"StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::" + core.Aws.ACCOUNT_ID + ":role/" + CfnParamBaseIAMRole.value_as_string
                    ]
                }
                }
            )
        )

        core.CfnOutput(
            self,
            "SecurityDeployRoleArn",
            description="Role ARN to be assumed for resource deployment",
            value=security_deploy_role.role_arn,
        )

        with open("analytics/cloudtrail/cloudtrail_demo_queries.sql") as f:
            sql_string = f.read()
        f.close()
        cloudtrail_queries = aws_athena.CfnNamedQuery(
            self,
            "CloudTrailQueries",
            database=glue_database.database_input.name,
            work_group=athena_workgroup.name,
            description="Example CloudTrail Athena Queries",
            name="CloudTrailExampleQueries",
            query_string=sql_string,
        )
        cloudtrail_queries.add_depends_on(athena_workgroup)
        cloudtrail_queries.add_depends_on(glue_database)

        with open("analytics/dns/dns_demo_queries.sql") as f:
            sql_string = f.read()
        f.close()
        dns_queries = aws_athena.CfnNamedQuery(
            self,
            "DNSQueries",
            database=glue_database.database_input.name,
            work_group=athena_workgroup.name,
            description="Example DNS Athena Queries",
            name="DNSExampleQueries",
            query_string=sql_string,
        )
        dns_queries.add_depends_on(athena_workgroup)
        dns_queries.add_depends_on(glue_database)

        with open("analytics/vpcflow/vpcflow_demo_queries.sql") as f:
            sql_string = f.read()
        f.close()
        vpcflow_queries = aws_athena.CfnNamedQuery(
            self,
            "vpcflowQueries",
            database=glue_database.database_input.name,
            work_group=athena_workgroup.name,
            description="Example VPC Flow Athena Queries",
            name="VPCFlowExampleQueries",
            query_string=sql_string,
        )
        vpcflow_queries.add_depends_on(athena_workgroup)
        vpcflow_queries.add_depends_on(glue_database)

        exposed_credential_policy = aws_iam.ManagedPolicy(
            self,
            "SystemIntegrationPolicy",
            statements=[
                aws_iam.PolicyStatement(
                    sid="AllowIAM",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["iam:*"],
                    resources=["*"]
                )
            ]
        )

        exposed_credential = aws_iam.User(
            self,
            "CredentialExposure",
            user_name="integration",
            managed_policies=[exposed_credential_policy],
        )

        exposed_credential_access_key = aws_iam.CfnAccessKey(
            self,
            "CredentialExposureAccessKey",
            user_name=exposed_credential.user_name,
            serial=None,
            status="Active",
        )

        core.CfnOutput(
            self,
            "CredentialExposureAccessKeySecret",
            description="IAM user access key secret for exposed credential scenario",
            value=exposed_credential_access_key.attr_secret_access_key,
        )

        core.CfnOutput(
            self,
            "CredentialExposureAccessKeyId",
            description="IAM user access key id for exposed credential scenario",
            value=exposed_credential_access_key.ref,
        )

        crypto_mining_credential_policy = aws_iam.ManagedPolicy(
            self,
            "CryptoMiningPolicy",
            statements=[
                aws_iam.PolicyStatement(
                    sid="AllowEC2",
                    effect=aws_iam.Effect.ALLOW,
                    actions=["ec2:*"],
                    resources=["*"]
                )
            ]
        )

        crypto_mining_credential = aws_iam.User(
            self,
            "CryptoMiningCredential",
            user_name="pipeline",
            managed_policies=[crypto_mining_credential_policy],
        )

        crypto_mining_credential_access_key = aws_iam.CfnAccessKey(
            self,
            "CryptoMiningAccessKey",
            user_name=crypto_mining_credential.user_name,
            serial=None,
            status="Active",
        )

        core.CfnOutput(
            self,
            "CryptoMiningAccessKeySecret",
            description="IAM user access key secret for crypto mining scenario",
            value=crypto_mining_credential_access_key.attr_secret_access_key,
        )

        core.CfnOutput(
            self,
            "CryptoMiningAccessKeyId",
            description="IAM user access key id for crypto mining scenario",
            value=crypto_mining_credential_access_key.ref,
        )