# Version [1.1] - 2023-07-07

## Changes

### WorkShop Stack
* Upgraded to AWS CDK version `2.87.0`
* EC2 instance type changed to `t3.small`
* Removed CDK metadata from cdk.out/WorkshopStack.yaml
* Added script for CDK metadata from CloudFormation template for direct deployment to CloudFormation without using AWS CDK

### Playbooks
* Not applicable

# Version [1.0] - 2023-05-25

## Changes

### WorkShop Stack
* Upgraded to AWS CDK v2
* Updated AWS CDK constructs to new version
* EC2 instance connect via AWS Systems Manager
* EC2 instance opened to the internet for simulations
* S3 Buckets using new defaults (no ACL, no Public Access)
* Added [permissions](https://docs.aws.amazon.com/guardduty/latest/ug/security_iam_id-based-policy-examples.html#guardduty_enable-permissions) to enable GuardDuty to the Security Deploy role

### Playbooks
* Not applicable

# Version [0.9] - 2021-11-24

## Changes

### WorkShop Stack
* Added CloudShell entitlements to all roles

### Playbooks
* Not applicable

# Version [0.8] - 2021-11-19

## Changes

### WorkShop Stack
* Not applicable

### Playbooks
* added to simulation folder scripts to remove resources created by simulation

# Version [0.7] - 2021-11-15

## Changes

### WorkShop Stack
* Not applicable

### Playbooks
* Comments added to simulation scripts 

# Version [0.6] - 2021-11-09

## Changes

### WorkShop Stack
* CloudFormation parameter changed to accept IAM User or Role as the principal to assume Security role

### Playbooks
* Typo with `aws s3 rb` command results

# Version [0.5] - 2021-11-01

## Changes

### WorkShop Stack
* Added ReadOnlyAccess permissions to SecurityDeployRole

### Playbooks
* Added IAM entitlements required to run playbook


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

