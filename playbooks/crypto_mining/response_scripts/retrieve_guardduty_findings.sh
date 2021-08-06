#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# requirements: AWS CLI profile, AWS Region, jq, GuardDuty finding type
# example: ```./retrieve_guardduty_findings.sh security_analyst us-east-1 '"CryptoCurrency:EC2/BitcoinTool.B!DNS"'```
# jq download https://stedolan.github.io/jq/download/
# GuardDuty finding types https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
PROFILE=${1}
REGION=${2}
FINDING_TYPE=${3}
detector_id=$(aws guardduty list-detectors --region ${REGION} --profile ${PROFILE} | jq -r '.DetectorIds[]')
echo "detector ID ${detector_id}"
finding_ids=$(aws guardduty list-findings --detector-id ${detector_id} --finding-criteria '{"Criterion": {"type": {"Eq": ['${FINDING_TYPE}']}}}' --region ${REGION} --profile ${PROFILE} | jq -r '.FindingIds[]')
echo "finding IDs ${finding_ids}"
echo "this might take some time, please wait"
instance_ids=$(for finding_id in ${finding_ids}; do aws guardduty get-findings --detector-id ${detector_id} --finding-id ${finding_id} --region ${REGION} --profile ${PROFILE}; done | jq -r '.Findings[].Resource.InstanceDetails.InstanceId')
echo "instance IDs ${instance_ids}"
echo ${instance_ids} > instance_ids.txt

