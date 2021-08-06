#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# requirements: AWS CLI profile, jq, AWS Region
# example: ```./simulate_crypto_mining_activity.sh crypto_mining us-east-1```
# jq download https://stedolan.github.io/jq/download/
#
PROFILE=${1}
REGION=${2}
echo "retrieving AMZN Linux 2 AMI id"
base_ami=$(aws ec2 describe-images --owners amazon --filters "Name=name,Values=amzn2-ami-hvm-2.0.????????.?-x86_64-gp2" "Name=state,Values=available" --query "reverse(sort_by(Images, &CreationDate))[:1].ImageId" --output text --region ${REGION} --profile ${PROFILE})
echo "enumerates all VPCs available"
vpcs=$(aws ec2 describe-vpcs --region ${REGION} --profile ${PROFILE} | jq -r '.Vpcs[].VpcId')
for vpc in ${vpcs}; do
  echo "spinning instances in all subnets of VPC ${vpcs}"
  subnets=$(aws ec2 describe-subnets --filters Name="vpc-id",Values="${vpc}" --region ${REGION} --profile ${PROFILE} | jq -r '.Subnets[].SubnetId')
  for subnet in ${subnets}; do
    spun=$(aws ec2 run-instances --user-data file://userdata.sh --image-id ${base_ami} --subnet-id ${subnet} --instance-type t2.nano --region ${REGION} --profile ${PROFILE}| jq -r '.Instances[].InstanceId')
    echo "crypto mining started - EC2 instance ${spun} in subnet ${subnet} of VPC ${vpc} using AMI ${ami_bitcoin}"
  done
done
