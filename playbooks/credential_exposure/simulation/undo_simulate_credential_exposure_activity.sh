#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# usage `./undo_simulate_credential_exposure_activity.sh
# requirement: use AWS CloudShell with AssumeRole SecurityBreakGlass
# use case: deletes resources created by simulation using files `bucket.resources and user.resources` as input
#
PERSISTENCE_USER=$(cat user.resources)
BUCKET_NAME=$(cat bucket.resources)
echo "trying to delete IAM User ${PERSISTENCE_USER}"
user_policy_arn=$(aws iam list-attached-user-policies --user-name ${PERSISTENCE_USER} | jq -r '.AttachedPolicies[].PolicyArn')
aws iam detach-user-policy --user-name ${PERSISTENCE_USER} --policy-arn ${user_policy_arn} &> /dev/null
access_key_id=$(aws iam list-access-keys --user-name ${PERSISTENCE_USER} | jq -r '.AccessKeyMetadata[].AccessKeyId')
aws iam delete-access-key --user-name ${PERSISTENCE_USER} --access-key-id ${access_key_id} &> /dev/null
aws iam delete-user --user-name ${PERSISTENCE_USER} &> /dev/null
error=${?}
if [ ${error} -ne 0 ]
   then
      echo "delete for IAM User ${PERSISTENCE_USER} returned error code ${error}"
   else
     echo "deletion succeeded for IAM User ${PERSISTENCE_USER} returned code ${error}"
fi
echo "trying to delete S3 Bucket ${BUCKET_NAME}"
aws s3 rb s3:${BUCKET_NAME} --force &> /dev/null
error=${?}
if [ ${error} -ne 252 ]
   then
     echo "delete for S3 Bucket ${BUCKET_NAME} returned error code ${error}"
   else
     echo "deletion for S3 Bucket ${BUCKET_NAME} returned code ${error}"
fi
echo "end of ${0}"

