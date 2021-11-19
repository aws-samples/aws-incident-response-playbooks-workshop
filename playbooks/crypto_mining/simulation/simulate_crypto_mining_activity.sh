#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# requirements: AWS CLI profile, jq, AWS Region
# example: ```./simulate_crypto_mining_activity.sh crypto_mining us-east-1```
# jq download https://stedolan.github.io/jq/download/
#
# Activity generated:
# - discovery of public Amazon Linux 2 AMIs available in region
# - discovery of VPCs available in AWS account
# - discovery of Networks available in VPCs
# - spin one t2.nano EC2 instance in each subnet for each VPC found
# - EC2 instance has userdata defined in file `userdata.sh`
# - `userdata.sh` performs multiple `dig` commands against known crypto currency related domains. no information
#    is exchanged. if GuardDuty is enabled, will trigger crypto mining DNS findings.
PROFILE=${1}
REGION=${2}
echo "retrieving AMZN Linux 2 AMI id"
base_ami=$(aws ec2 describe-images --owners amazon --filters "Name=name,Values=amzn2-ami-hvm-2.0.????????.?-x86_64-gp2" "Name=state,Values=available" --query "reverse(sort_by(Images, &CreationDate))[:1].ImageId" --output text --region ${REGION} --profile ${PROFILE})
echo "enumerates all VPCs available"
vpcs=$(aws ec2 describe-vpcs --region ${REGION} --profile ${PROFILE} | jq -r '.Vpcs[].VpcId')
echo "" > instances.resources
for vpc in ${vpcs}; do
  echo "spinning instances in all subnets of VPC ${vpcs}"
  subnets=$(aws ec2 describe-subnets --filters Name="vpc-id",Values="${vpc}" --region ${REGION} --profile ${PROFILE} | jq -r '.Subnets[].SubnetId')
  for subnet in ${subnets}; do
    spun=$(aws ec2 run-instances --user-data file://userdata.sh --image-id ${base_ami} --subnet-id ${subnet} --instance-type t2.nano --region ${REGION} --profile ${PROFILE}| jq -r '.Instances[].InstanceId')
    echo "crypto mining started - EC2 instance ${spun} in subnet ${subnet} of VPC ${vpc} using AMI ${ami_bitcoin}"
    echo "${spun} " >> instances.resources
  done
done
echo "resources created to be deleted after playbook is completed"
echo "EC2 instances $(cat instances.resources)"
echo "save the file instances.resources for future use by the bash script undo_simulate_crypto_mining_activity.sh"
echo "end of ${0}"
