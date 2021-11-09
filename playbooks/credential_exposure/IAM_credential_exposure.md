---

PLEASE NOTE THIS PLAYBOOK USES FICTITIOUS ENTITIES SUCH AS ```AKIAIOSFODNN7EXAMPLE``` FOR *IAM ACCESS KEY ID*, ```198.51.100.77``` FOR *IP ADDRESS*, AND ARBITRARY *DATE RANGES* FOR ATHENA QUERIES AND AWS CLI COMMANDS. YOU WILL NEED TO REPLACE THOSE WITH ACTUALS FROM THE AWS ACCOUNT YOU ARE USING. 

---

# IAM credential exposure playbook

## Preparation

### The threat

This playbook covers the detection of exposed IAM credentials in the form of *IAM Access Keys* or *IAM User and password combination*. It does not cover *AWS account root user*. If a non-authorized actor has a copy of those credentials, they can perform any action in your account permitted by the policies associated with those credentials, such as launching an Amazon EC2 instance and storing objects in Amazon S3. Privileges could be escalated either by exploiting vulnerabilities or misuse of ancillary entitlements. Detective controls for exposed IAM credentials should be defined and implemented based on threat modeling, e.g. notification from third party, Data Loss Prevention (DLP) systems, or unusual AWS API call activity (deterministic(*) or AI/ML based). 

(*) Deterministic based means using a static rule, e.g. EC2 RunInstances API CALL is made by a IP address belonging to CIDR 198.51.100.0/24 using permanent access keys with user agent “Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246”.

### Objectives

Throughout the execution of the playbook, focus on the _***desired outcomes***_, taking notes for enhancement of incident response capabilities.

#### Determine: 

* **Vulnerabilities exploited**
* **Exploits and tools observed**
* **Actor's intent**
* **Actor's attribution**
* **Damage inflicted to the environment and business**

#### Recover:

* **Return to original and hardened configuration**

#### Enhance CAF Security Perspective components:
[AWS Cloud Adoption Framework Security Perspective](https://d0.awsstatic.com/whitepapers/AWS_CAF_Security_Perspective.pdf)
* **Directive**
* **Detective**
* **Responsive**
* **Preventative**

![Image](images/aws_caf.png)
* * *


### Response Steps

1. [**ANALYSIS**] Validate alert by checking ownership of exposed credential
2. [**ANALYSIS**] Identity exposed credential owner/custodian
3. [**CONTAINMENT**] Disable exposed credential if approved by owner/customer
4. [**ANALYSIS**] Use Athena to pull 15 days of exposed credential activity from CloudTrail logs
5. [**ANALYSIS**] Use Athena to pull 15 days of source IP addresses used by exposed credential from VPC Flow logs 
6. [**ANALYSIS**] Establish reputation for source IP addresses
7. [**ANALYSIS**] Determine which source IP addresses were used against infrastructure resources such as EC2 instances, RDS databases   
8. [**ANALYSIS**] Discover all resources provisioned, modified, and deleted by the exposed credential based on CloudTrail logs
9. [**CONTAINMENT**] Perform containment of all rogue resources provisioned by the exposed credential
10. [**CONTAINMENT**] Perform containment of existing resources modified by the exposed credentials with approval from owner/custodian
11. [**ANALYSIS**] Repeat steps 4 to 10 for IAM principals created by the exposed credential
11. [**ANALYSIS**] Determine if data was exfiltrated, modified, or deleted. Figure out the classification for all data sets touched.
12. [**ANALYSIS**] Expand log scope to 90 days or further and repeat steps 1-12. Use your judgment on how far back to go.
13. [**ANALYSIS**] Estimate attribution and attack type (targeted or opportunistic)
14. [**ANALYSIS**] Preserve all relevant infrastructure and service resources for forensics investigation
15. [**ERADICATION**] Perform eradication (delete rogue resources, apply security updates and harden configuration)
16. [**RECOVERY**] Perform recovery by restoring system data and rebuilding components
17. [**POST-INCIDENT ACTIVITY**] Perform post-incident activity for preparation enhancement


***The response steps follow the Incident Response Life Cycle from NIST Special Publication 800-61r2
[NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
![Image](images/nist_life_cycle.png)***


### Incident Classification & Handling

* **Tactics, techniques, and procedures**: Exfiltration of credentials
* **Category**: IAM credential exposure
* **Resource**: IAM
* **Roles to Assume**:
  * **SecurityAnalystRole**: provides Athena querying and GuardDuty R/O access
  * **AthenaAdminRole**: configure and maintain Athena
  * **SecurityDeployRole**: deploy AWS CDK app or CloudFormation stacks
  * **SecurityBreakGlassRole**: account administrator, for any incident response related activity requiring elevation upon approval 
* **Tooling**: [AWS Command Line Interface](https://docs.aws.amazon.com/cli/latest/index.html) (CLI), [Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/querying-AWS-service-logs.html)
* **Indicators**: Cyber Threat Intelligence, Third Party Notice
* **Log Sources**: AWS CloudTrail, AWS Config, VPC Flow Logs, Amazon GuardDuty
* **Teams**: Security Operations Center (SOC), Forensic Investigators, Cloud Engineering

* * *

### Activity simulated for this playbook

The file ```simulation/simulate_credential_exposure_activity.sh``` is a bash script using AWS CLI simulating an actor using IAM User Access Keys for reconnaissance, elevation of privileges, and persistence. 

* * *

### IAM entitlements used for this playbook

The following IAM Roles are available in the AWS account to assume

#### SecurityAnalystRole
- For Athena queries: custom IAM Policy
- To perform analysis tasks: [ReadOnlyAccess](https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/ReadOnlyAccess) 

#### SecurityDeployRole
- For resource deployment using CloudFormation

#### SecurityBreakGlassRole
- To perform containment, and eradication tasks: [AdministratorAccess](https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/AdministratorAccess)

#### SecurityAdminRole
- To perform security tool administrative tasks such as Athena or GuardDuty administration: customer IAM Policy

## Assuming Roles: 
- CloudShell provides a Linux shell environment with temporary credentials associated with the current IAM Role you are signed in to the console. The AWS CLI will use these session tokens by default.
- Alternatively you can install the AWS CLI in Windows, Linux, and MacOS and configure multiple IAM Roles to be assumed using the `-- profile` parameter.

**All examples in this playbook use the `--profile` parameter to indicate the IAM Role required for the AWS CLI command. If you use CloudShell, remove the `--profile` parameter from the AWS CLI call.**

* * *


## Incident Handling Process

### The incident response process has the following stages:

* Part 1: Analysis - Validation
* Part 2: Analysis - Scope
* Part 3: Analysis - Impact
* Part 4: Containment
* Part 5: Eradication
* Part 6: Recovery 
* Part 7: Post-Incident Activity

* * *

### Part 1: Analysis - Validation

IAM Access Key with id AKIAIOSFODNN7EXAMPLE was found in plain text in a public git repository.

There are no technical detective controls to validate, therefore, check ownership of the IAM Access Key ID using the AWS CLI:
```
aws sts get-access-key-info --access-key-id AKIAIOSFODNN7EXAMPLE --profile SecurityAnalystRole --region us-east-1
{
    "Account": "777777777777"
}
```

If AWS account 777777777777 is owned by you, continue to Analysis, otherwise inform [AWS Trust and Safety Team](https://aws.amazon.com/premiumsupport/knowledge-center/report-aws-abuse/) of the found IAM Access Key ID.

* * *

### Part 2: Analysis - Scope

Assume the SecurityAnalystRole on the AWS account hosting the Athena workgroup IRWorkshopWorkgroup.

1. Retrieve past 7 days of the following activity for IAM Access Key ID AKIAIOSFODNN7EXAMPLE:
    * Service activity (API calls) from CloudTrail logs
    * Infrastructure and application network activity from VPC Flow logs based on the source IP addresses used for API calls
2. Establish reputation for source IP address list: 
    * Use internal and external threat intelligence
    * Who owns the source IP addresses used?
3. Using API call history, determine resources created, modified, deleted, and probed:
4. Document resource inventory by AWS Service and call made

#### Athena Queries and AWS CLI calls


```
-- retrieve past 7 days of API calls
SELECT awsregion, eventsource, eventname, readonly, errorcode, errormessage, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.accesskeyid = 'AKIAIOSFODNN7EXAMPLE'
      AND date_partition >= '2021/07/16'
      AND date_partition <= '2021/07/24'
GROUP BY awsregion, eventsource, eventname, readonly, errorcode, errormessage
ORDER BY COUNT DESC
```

```
awsregion  |  eventsource        |  eventname          |  readonly  |  errorcode  |  errormessage  |  COUNT
-----------|---------------------|---------------------|------------|-------------|----------------|-------
us-east-1  |  sts.amazonaws.com  |  GetCallerIdentity  |  true      |             |                |  1
us-east-1  |  iam.amazonaws.com  |  AttachUserPolicy   |  false     |             |                |  1
us-east-1  |  iam.amazonaws.com  |  CreateUser         |  false     |             |                |  1
us-east-1  |  iam.amazonaws.com  |  CreateAccessKey    |  false     |             |                |  1
```


```
-- retrieve past 7 days of source IP addresses and user agents used for API calls
SELECT sourceipaddress, useragent, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.accesskeyid = 'AKIAIOSFODNN7EXAMPLE'
      AND date_partition >= '2021/07/16'
      AND date_partition <= '2021/07/24'
GROUP BY sourceipaddress, useragent
ORDER BY COUNT DESC
```


sourceipaddress  |  useragent                                                                                       |  COUNT
-----------------|--------------------------------------------------------------------------------------------------|-------
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/iam.create-access-key    |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/sts.get-caller-identity  |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/iam.attach-user-policy   |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/iam.create-user          |  1


```
-- retrieve past 7 days of infrastructure and application network activity       
SELECT "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress, 
       "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress,
       count(*) as count
FROM "irworkshopgluedatabase"."irworkshopgluetablevpcflow" 
INNER JOIN "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
ON ("irworkshopgluedatabase"."irworkshopgluetablecloudtrail".sourceipaddress = 
   "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress)
   OR
   ("irworkshopgluedatabase"."irworkshopgluetablecloudtrail".sourceipaddress = 
   "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress)
WHERE "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".useridentity.accesskeyid = 'AKIAIOSFODNN7EXAMPLE'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition >= '2021/07/16'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition <= '2021/07/24'
GROUP BY "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress, 
         "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress
ORDER BY count DESC
```

```
Zero records returned.
```

#### Analysis of Athena query results:

* The actor performed changes to the services with the API calls AttachUserPolicy, CreateUser, and CreateAccessKey. They probed  services using GetCallerIdentity.  

* Source IP address reputation:
   * ExoneraTor: The ExoneraTor service maintains a database of IP addresses that have been part of the Tor network. 
      * https://metrics.torproject.org/exonerator.html?ip=198.51.100.77×tamp=2021-07-24&lang=en
   * Greynoise:
      * IP reputation service
         * https://www.greynoise.io/viz/query/?gnql=198.51.100.77
   * Whois:
      * There are several options to acquire WHOIS information, here is one directly from CLI for one of the IP addresses
         * ```whois 198.51.100.77```
* No infrastructure and application network activity was detected.   

#### Additional Athena queries:

* We need to analyze the changes made with the AttachUserPolicy, CreateUser, and CreateAccessKey API calls.

```
-- retrieve additional information about changes made to the services
SELECT eventtime, awsregion, eventname, requestparameters, responseelements, errorcode, errormessage
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.accesskeyid = 'AKIAIOSFODNN7EXAMPLE'
      AND date_partition >= '2021/07/16'
      AND date_partition <= '2021/07/24'
      AND eventname IN ('AttachUserPolicy', 'CreateUser', 'CreateAccessKey')
```

eventtime             |  awsregion  |  eventname         |  requestparameters                                                                                                       |  responseelements                                                                                                                                                                                                                               |  errorcode  |  errormessage
----------------------|-------------|--------------------|--------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|--------------
2021-07-24T02:22:32Z  |  us-east-1  |  CreateUser        |  {"userName":"JaneDoe"}                                                            |  {"user":{"path":"/","userName":"JaneDoe","userId":"AIDACKCEVSQ6C2EXAMPLE","arn":"arn:aws:iam::777777777777:user/JaneDoe","createDate":"Jul 24, 2021 2:22:32 AM"}}  |             |
2021-07-24T02:22:34Z  |  us-east-1  |  CreateAccessKey   |  {"userName":"JaneDoe"}                                                            |  {"accessKey":{"userName":"JaneDoe","accessKeyId":"AKIAI44QH8DHBEXAMPLE","status":"Active","createDate":"Jul 24, 2021 2:22:34 AM"}}                                                                       |             |
2021-07-24T02:22:33Z  |  us-east-1  |  AttachUserPolicy  |  {"userName":"JaneDoe","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}  |  null                                                                                                                                                                                                                                           |             |


* The IAM User ```JaneDoe``` was created with the AWS managed policy ```AdministratorAccess``` attached and Access Key ID ```AKIAI44QH8DHBEXAMPLE```.

```
-- retrieve API call activity of rogue user
SELECT awsregion, eventsource, eventname, readonly, errorcode, errormessage, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.username = 'JaneDoe'
      AND date_partition >= '2021/07/16'
      AND date_partition <= '2021/07/24'
GROUP BY awsregion, eventsource, eventname, readonly, errorcode, errormessage
ORDER BY COUNT DESC
```

awsregion  |  eventsource                   |  eventname              |  readonly  |  errorcode  |  errormessage  |  COUNT
-----------|--------------------------------|-------------------------|------------|-------------|----------------|-------
us-east-1  |  sts.amazonaws.com             |  GetCallerIdentity      |  true      |             |                |  2
us-east-1  |  iam.amazonaws.com             |  ListRoles              |  true      |             |                |  1
us-east-1  |  logs.amazonaws.com            |  DescribeDestinations   |  true      |             |                |  1
us-east-1  |  s3.amazonaws.com              |  CreateBucket           |  false     |             |                |  1
us-east-1  |  kms.amazonaws.com             |  ListKeys               |  true      |             |                |  1
us-east-1  |  lambda.amazonaws.com          |  ListFunctions20150331  |  true      |             |                |  1
us-east-1  |  s3.amazonaws.com              |  ListBuckets            |  true      |             |                |  1
us-east-1  |  secretsmanager.amazonaws.com  |  ListSecrets            |  true      |             |                |  1
us-east-1  |  kms.amazonaws.com             |  ListAliases            |  true      |             |                |  1
us-east-1  |  s3.amazonaws.com              |  PutObject              |  false     |             |                |  1
us-east-1  |  ec2.amazonaws.com             |  DescribeInstances      |  true      |             |                |  1

```
-- retrieve rogue user source IP addresses and user agents used for API calls
SELECT sourceipaddress, useragent, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.username = 'JaneDoe'
      AND date_partition >= '2021/07/16'
      AND date_partition <= '2021/07/24'
GROUP BY sourceipaddress, useragent
ORDER BY COUNT DESC
```

sourceipaddress  |  useragent                                                                                           |  COUNT
-----------------|------------------------------------------------------------------------------------------------------|-------
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/sts.get-caller-identity      |  2
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/lambda.list-functions        |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/ec2.describe-instances       |  1
198.51.100.77     |  [aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/s3api.put-object]           |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/secretsmanager.list-secrets  |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/iam.list-roles               |  1
198.51.100.77     |  [aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/s3api.create-bucket]        |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/kms.list-aliases             |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/logs.describe-destinations   |  1
72.21.198.71     |  [aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/s3api.list-buckets]         |  1
198.51.100.77     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/kms.list-keys                |  1

* No new source IP addresses surfaced
* We need to analyze the changes made with the CreateBucket, and PutObject API calls.
* We need to analyze the probing made with the ListRoles, DescribeDestinations, ListKeys, ListFunctions20150331, ListBuckets, ListSecrets, ListAliases, and DescribeInstances API calls.

```
-- retrieve additional information about the rogue user changes
SELECT eventtime, awsregion, eventname, requestparameters, responseelements, errorcode, errormessage
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.username = 'JaneDoe'
      AND date_partition >= '2021/07/16'
      AND date_partition <= '2021/07/24'
      AND eventname IN ('CreateBucket', 'PutObject')
```

eventtime             |  awsregion  |  eventname     |  requestparameters                                                                                                                                                   |  responseelements  |  errorcode  |  errormessage
----------------------|-------------|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|-------------|--------------
2021-07-24T02:22:56Z  |  us-east-1  |  CreateBucket  |  {"bucketName":"DOC-EXAMPLE-BUCKET","Host":"DOC-EXAMPLE-BUCKET.s3.us-east-1.amazonaws.com"}                |  null              |             |
2021-07-24T02:22:57Z  |  us-east-1  |  PutObject     |  {"bucketName":"DOC-EXAMPLE-BUCKET","Host":"DOC-EXAMPLE-BUCKET.s3.us-east-1.amazonaws.com","key":"stuff"}  |  null              |             |

* S3 Bucket name ```DOC-EXAMPLE-BUCKET``` was created and an object with key ```stuff``` was placed in it.

```
-- retrieve additional information about the rogue user probing
SELECT eventtime, awsregion, requestparameters, responseelements, errorcode, errormessage
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.username = 'JaneDoe'
      AND date_partition >= '2021/07/16'
      AND date_partition <= '2021/07/24'
      AND eventname IN ('ListRoles', 'DescribeDestinations', 'ListKeys', 'ListFunctions20150331', 'ListBuckets', 'ListSecrets', 'ListAliases', 'DescribeInstances')
```

eventtime             |  awsregion  |  requestparameters                      |  responseelements  |  errorcode  |  errormessage
----------------------|-------------|-----------------------------------------|--------------------|-------------|--------------
2021-07-24T02:22:45Z  |  us-east-1  |  null                                   |  null              |             |
2021-07-24T02:22:48Z  |  us-east-1  |  null                                   |  null              |             |
2021-07-24T02:22:51Z  |  us-east-1  |  {"Host":"s3.us-east-1.amazonaws.com"}  |  null              |             |
2021-07-24T02:22:52Z  |  us-east-1  |  {"instancesSet":{},"filterSet":{}}     |  null              |             |
2021-07-24T02:22:53Z  |  us-east-1  |  null                                   |  null              |             |
2021-07-24T02:22:46Z  |  us-east-1  |  null                                   |  null              |             |
2021-07-24T02:22:49Z  |  us-east-1  |  null                                   |  null              |             |
2021-07-24T02:22:50Z  |  us-east-1  |  null                                   |  null              |             |

* CloudTrail does not hold the information about the probed resources.

* Attempt to retrieve the object from the S3 Bucket using AWS CLI:
```
aws s3api get-object --bucket DOC-EXAMPLE-BUCKET --key stuff stuff --profile SecurityAnalystRole

{
    "AcceptRanges": "bytes",
    "LastModified": "2021-07-24T02:22:58+00:00",
    "ContentLength": 43860,
    "ETag": "\"3551a9d2-22cd-481e-92ee-639334e18c43\"",
    "ContentType": "binary/octet-stream",
    "Metadata": {}
}
```

* The contents of the file are the outputs of the probing API calls ```../evidence/stuff ```

* Attempt to retrieve the S3 Bucket policy using AWS CLI:
```
aws s3api get-bucket-policy --bucket DOC-EXAMPLE-BUCKET  --profile SecurityAnalystRole

An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist

```

* Attempt to retrieve the S3 Bucket ACL using AWS CLI:
```
aws s3api get-bucket-acl --bucket DOC-EXAMPLE-BUCKET  --profile SecurityAnalystRole

{
    "Owner": {
        "DisplayName": "maymajor",
        "ID": "e810532a-fef5-4ebd-b8f4-2ca52fea3b46"
    },
    "Grants": [
        {
            "Grantee": {
                "DisplayName": "maymajor",
                "ID": "e810532a-fef5-4ebd-b8f4-2ca52fea3b46",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        }
    ]
}

```

* * *

### Part 3: Analysis - Impact

Parse through the distilled information looking for patterns, extrapolate into behaviors that contrast with expected baseline of approved activity. Take a holistic approach looking at the data presented to you and continuously ask yourself if the constructed patterns represent normal behavior, external actor, or insider. The following questions will serve as a guide, but don’t limit yourself, expand based on your own findings and doubts. Make sure to have *data* backing up your answers:

1. What related alerts have been triggered? 
   * No related alerts have been triggered
2. What is the classification of the data accessed?
   * The service resource's configuration probed by the actor is classified as "Internal"
3. What AWS services are not in the approved use list? 
   * All services accessed by the actor are allowed to be used by authorized users
4. What AWS service configurations have been changed?
   * S3 Bucket name ```DOC-EXAMPLE-BUCKET``` was created and an object with key ```stuff``` was placed in it.
   * The IAM User ```JaneDoe``` was created with the AWS managed policy ```AdministratorAccess``` attached and Access Key ID ```AKIAI44QH8DHBEXAMPLE```.
5. What guardrails have been disabled or modified? 
   * None
6. Was the actor an insider or outsider?
   * An internal investigation has started, at the moment no evidence of insider activity
7. What evidence supports benign and malicious activity? 
   * API calls logged in CloudTrail 
   * Object (text file) uploaded by actor to S3 bucket contains probing information 
8. What is the impact to business applications and processes? 
   * Escalating to owner of exposed credential. This credential was for a test in the development environment and has not affected production.
9. Is there any indication of possible data exfiltration? 
   * Yes, probing information about the development account ```777777777777``` resources

* * *

### Part 4: Containment

The user ```JorgeSouza``` was the initial compromise vector, which created another user ```JaneDoe``` which in turn created the S3 bucket ```DOC-EXAMPLE-BUCKET```.

#### Resource list for account ```777777777777```:
   * S3 Bucket: ```DOC-EXAMPLE-BUCKET```
   * IAM User: ```JorgeSouza``` and IAM Access Key ID: ```AKIAIOSFODNN7EXAMPLE``` 
   * IAM User: ```JaneDoe``` and IAM Access Key ID: ```AKIAI44QH8DHBEXAMPLE```

#### Containment actions:

* Disable IAM Access Key IDs ```AKIAIOSFODNN7EXAMPLE``` and ```AKIAI44QH8DHBEXAMPLE``` and verify:

Please note IAM is [eventually consistent](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency), if during verification the ```"Status"``` shows ```"Active"```, just ```list-access-keys again``` and the ```"Status"``` will eventually show up as ```"Inactive"```.

```
aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name JorgeSouza --profile SecurityBreakGlassRole
(no output)


aws iam list-access-keys --user-name JorgeSouza
{
    "AccessKeyMetadata": [
        {
            "UserName": "JorgeSouza",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Inactive",
            "CreateDate": "2021-07-24T02:31:19+00:00"
        }
    ]
}


aws iam update-access-key --access-key-id AKIAI44QH8DHBEXAMPLE --status Inactive  --user-name JaneDoe --profile SecurityBreakGlassRole
(no output)

aws iam list-access-keys --user-name JaneDoe
{
    "AccessKeyMetadata": [
        {
            "UserName": "JaneDoe",
            "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
            "Status": "Inactive",
            "CreateDate": "2021-07-24T02:22:34+00:00"
        }
    ]
}

```

* Attach the following policy to IAM Users ```JaneDoe``` and ```JorgeSouza``` and verify:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IamPolicyForContainment",
      "Action": "*",
      "Effect": "Deny",
      "Resource": "*"
    }
  ]
}
```

```
aws iam create-policy --policy-name iam-containment-policy --policy-document file://containment/iam_containment_policy.json --profile SecurityBreakGlassRole
{
    "Policy": {
        "PolicyName": "iam-containment-policy",
        "PolicyId": "ANPAJ2UCCR6DPCEXAMPLE",
        "Arn": "arn:aws:iam::777777777777:policy/iam-containment-policy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2021-07-26T00:37:18+00:00",
        "UpdateDate": "2021-07-26T00:37:18+00:00"
    }
}
aws iam attach-user-policy --policy-arn arn:aws:iam::777777777777:policy/iam-containment-policy --user-name JorgeSouza --profile SecurityBreakGlassRole
(no output)

aws iam list-attached-user-policies --user-name JorgeSouza
{
    "AttachedPolicies": [
        {
            "PolicyName": "iam-containment-policy",
            "PolicyArn": "arn:aws:iam::777777777777:policy/iam-containment-policy"
        },
        {
            "PolicyName": "SimulationStack-SystemJorgeSouzaPolicy6FA12ED7-1I709F3HY50FL",
            "PolicyArn": "arn:aws:iam::777777777777:policy/SimulationStack-SystemJorgeSouzaPolicy6FA12ED7-1I709F3HY50FL"
        }
    ]
}


aws iam attach-user-policy --policy-arn arn:aws:iam::777777777777:policy/iam-containment-policy --user-name JaneDoe --profile SecurityBreakGlassRole
(no output)

aws iam list-attached-user-policies --user-name JaneDoe --profile SecurityBreakGlassRole
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        {
            "PolicyName": "iam-containment-policy",
            "PolicyArn": "arn:aws:iam::777777777777:policy/iam-containment-policy"
        }
    ]
}

```

* Apply containment policy allowing forensics access without requiring root user for S3 Bucket ```DOC-EXAMPLE-BUCKET```.

```
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Condition": {
              "StringNotLike": {
                  "aws:PrincipalArn": [
                      "arn:aws:iam::777777777777:role/SecurityBreakGlassRole"
                  ]
              }
          },
          "Action": "*",
          "Resource": [
              "arn:aws:s3:::DOC-EXAMPLE-BUCKET",
              "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"
          ],
          "Effect": "Deny",
          "Principal": "*",
          "Sid": "BucketPolicyForContainment"
      }
  ]
}
```

```
aws s3api put-bucket-policy --bucket DOC-EXAMPLE-BUCKET --policy file://containment/s3_bucket_containment_policy.json --profile SecurityBreakGlassRole
(no output)

aws s3api get-bucket-policy --bucket DOC-EXAMPLE-BUCKET --profile SecurityBreakGlassRole | jq '[.[]|fromjson]' 
[
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "BucketPolicyForContainment",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "*",
        "Resource": [
          "arn:aws:s3:::DOC-EXAMPLE-BUCKET",
          "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"
        ],
        "Condition": {
          "StringNotLike": {
            "aws:PrincipalArn": "arn:aws:iam::777777777777:role/master"
          }
        }
      }
    ]
  }
]


```

* * *

### Part 5: Eradication

#### Resource list for account ```777777777777```:
   * S3 Bucket: ```DOC-EXAMPLE-BUCKET```
   * IAM User: ```JorgeSouza``` and IAM Access Key ID: ```AKIAIOSFODNN7EXAMPLE``` 
   * IAM User: ```JaneDoe``` and IAM Access Key ID: ```AKIAI44QH8DHBEXAMPLE```

***>>>>>THESE ACTIONS ARE FINAL AND UNRECOVERABLE<<<<<***

* Delete S3 Bucket
   * after preserving the objects in the S3 Bucket, force delete
```
aws s3 rb s3://DOC-EXAMPLE-BUCKET --force --profile SecurityBreakGlassRole
delete: s3://DOC-EXAMPLE-BUCKET/stuff
remove_bucket: DOC-EXAMPLE-BUCKET 

```

* Delete IAM Users

Please note IAM is [eventually consistent](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency), if during verification the users still exist, they will eventually be deleted.

```
aws iam detach-user-policy --user-name JorgeSouza --policy-arn arn:aws:iam::777777777777:policy/SimulationStack-SystemJorgeSouzaPolicy6FA12ED7-1I709F3HY50FL --profile SecurityBreakGlassRole
(no output)
aws iam detach-user-policy --user-name JorgeSouza --policy-arn arn:aws:iam::777777777777:policy/iam-containment-policy --profile SecurityBreakGlassRole
(no output)
aws iam delete-access-key --user-name JorgeSouza --access-key-id AKIAIOSFODNN7EXAMPLE --profile SecurityBreakGlassRole
(no output)
aws iam delete-user --user-name JorgeSouza --profile SecurityBreakGlassRole
(no output)
aws iam get-user --user-name JorgeSouza --profile SecurityBreakGlassRole

An error occurred (NoSuchEntity) when calling the GetUser operation: The user with name JorgeSouza cannot be found.




aws iam detach-user-policy --user-name JaneDoe --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile SecurityBreakGlassRole
(no output)
aws iam detach-user-policy --user-name JaneDoe --policy-arn arn:aws:iam::777777777777:policy/iam-containment-policy --profile SecurityBreakGlassRole
(no output)
aws iam delete-access-key --user-name JaneDoe --access-key-id AKIAI44QH8DHBEXAMPLE --profile SecurityBreakGlassRole
(no output)
aws iam delete-user --user-name JaneDoe --profile SecurityBreakGlassRole
(no output)
aws iam get-user --user-name JaneDoe --profile SecurityBreakGlassRole

An error occurred (NoSuchEntity) when calling the GetUser operation: The user with name JaneDoe cannot be found.

```

* * *

### Part 6: Recovery 

* No recovery steps required

* * *

### Part 7: Post-Incident Activity

**Recommendations:**
* Automate containment and eradication with AWS CLI or SDK
* Save all Athena queries used in the playbook for faster use
* Pursue eliminating use of long term IAM User Access Keys and adopt short term STS tokens
* Create alerts based on creation of long term IAM User Access Keys


