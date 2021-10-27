# Version [0.4] - 2021-10-27

## Changes

### WorkShop Stack
* Added cloudshell and cloudformation permissions to SecurityDeployRole


# Version [0.3] - 2021-10-13

## Changes

### CoreStack
* Removed GuardDuty
* Removed GuardDuty IAM Policy statement

# Version [0.2] - 2021-08-05

## Changes

### CoreStack
* Policy change for Deploy Role
* Removed unnecessary code comments
* Playbook grammar and syntax fixes

# Version [0.1] - 2021-07-22

## Features added

### CoreStack
* CloudTrail logging to S3 bucket
* VPC Flow logging to S3 Bucket
* DNS logging to S3 Bucket
* GuardDuty enabled
* Athena Workgroup 
* Glue database and tables for all log types
* IAM Role for Athena administration
* IAM Role for security analyst to use Athena

### SimulationStack
* IAM User Access Keys for crypto mining playbook simulation
* IAM User Access Keys for exposed credential playbook simulation

### Playbooks
* Credential exposure
* Crypto mining
* Template

