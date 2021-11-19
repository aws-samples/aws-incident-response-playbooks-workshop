#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# usage `./undo_simulate_crypto_mining_activity.sh
# requirement: use AWS CloudShell with AssumeRole SecurityBreakGlass
# use case: deletes resources created by simulation using file `instances.resources` as input
#
INSTANCES=$(cat instances.resources)
echo "trying to terminate EC2 instances ${INSTANCES}"
for instance in ${INSTANCES}; do
  aws ec2 terminate-instances --instance-ids ${instance}  &> /dev/null
  error=${?}
  if [ ${error} -ne 0 ]
    then
      echo "terminate failed for EC2 instance ${instance} with error ${error}"
  fi
done
echo "end of ${0}"

