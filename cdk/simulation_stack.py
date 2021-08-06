"""
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Building Incident Response Playbooks for AWS

## Simulation Stack
* Creates resources to be used by playbook scenario simulations

### completed:
* IAM user for 'credential exposed' scenario simulation
* IAM user for 'crypto mining' scenario simulation

### todo:

"""
from aws_cdk import (
    core,
    aws_iam,
)


class SimulationStack(core.Stack):
    def __init__(
            self, scope: core.Construct, construct_id: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

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
