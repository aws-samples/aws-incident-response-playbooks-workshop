# Threat name playbook

## The threat

[//]: # (Describe the threat this playbook addresses)

This playbook addresses threat alpha which would impact workload bravo. The alerts used to trigger this playbook are alert charlie from GuardDuty, or alert echo from CloudWatch Rule foxtrot. 

* * *

## Objectives

[//]: # (replace with your own words what are the expected outcomes by running this playbook)

Throughout the execution of the playbook, focus on the _***desired outcomes***_, taking notes for enhancement of incident response capabilities.

### Determine: 

* **Vulnerabilities exploited**
* **Exploits and tools observed**
* **Actor's intent**
* **Actor's attribution**
* **Damage inflicted to the environment and business**

### Recover:

* **Return to original and hardened configuration**

### Enhance CAF Security Perspective components:
[AWS Cloud Adoption Framework Security Perspective](https://d0.awsstatic.com/whitepapers/AWS_CAF_Security_Perspective.pdf)
* **Directive**
* **Detective**
* **Responsive**
* **Preventative**

![Image](images/aws_caf.png)
* * *

## Response steps

[//]: # (write down the steps to be taken labeling according to NIST 800-61r2 incident response life-cycle)

1. [**ANALYSIS**] Alert validation
2. [**ANALYSIS**] Scope of the incident
3. [**ANALYSIS**] Impact to environment
4. [**CONTAINMENT**] Perform containment
5. [**RECOVERY**] Perform recovery
6. [**ERADICATION**] Perform eradication (apply security updates and harden configuration)
7. [**RECOVERY**] Perform recovery by restoring system data and rebuilding components
8. [**POST-INCIDENT ACTIVITY**] Perform post-incident activity for preparation enhancement

### Incident Response Life Cycle (NIST 800-61r2)
[NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
![Image](images/nist_life_cycle.png)

* * *

## Activity simulated for this playbook

[//]: # (describe how the alerts can be simulated for playbook validation purposes)

1. Actor performs technique alpha
2. Actor performs technique bravo
3. Actor performs technique charlie

### Bash scripts found under the simulation directory. 

Example:

> ./simulate.sh us-west-2 111122223333 

```
#!/bin/bash
region=${1}
victim_account=${2}
echo "this script targets AWS Region=${region} and AWS Account id=${victim_account}"
```
Output from bash script:

```
output expected
```

* * *

## Incident Classification & Handling

[//]: # (categorize the incident according to your organization's standards)

* **Tactics, techniques, and procedures**: TTPs
* **Category**: Category
* **Resource**: Resources
* **Tooling**: [AWS Command Line Interface](https://docs.aws.amazon.com/cli/latest/index.html) (CLI), [Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/querying-AWS-service-logs.html)
* **Indicators**: 
    * Custom CloudWatch Rule
    * [GuardDuty Finding alpha](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
* **Log Sources**: AWS CloudTrail, VPC Flow, Route53 VPC DNS, Amazon GuardDuty
* **Teams**: Alpha, Bravo, and Charlie

* * *

## Incident Handling Process

### The incident response process is comprised of the following:

[//]: # (Detail the 'response steps' previously outlined)

* Part 1: Analysis - Validation
* Part 2: Analysis - Scope
* Part 3: Analysis - Impact
* Part 4: Containment
* Part 5: Eradication
* Part 6: Recovery 
* Part 7: Post-Incident Activity

### Part 1: Analysis - Validation

[//]: # (validate alert)

*Verify the integrity of the alert by checking if the indicator exists and comparing the alert data with the alert source. Any mismatch need to be notified to the team(s) responsible for designing, implementing, and maintaining the guardrail.* 

1. Compare alert data with alert source
3. If there is a mismatch, escalate to teams alpha, bravo, and charlie. Upon their response, if possible, continue with **Part 2: Analysis - Alert Triage**, otherwise continue to **Part 6: Post-Incident Activity**.
5. If there is a match, continue to **Part 2: Analysis - Alert Scope**


**Retrieve alert data**

[//]: # (describe how to retrieve the alert data to compare with the alert source)

```
retrieve alert data directions
```

**Queries used for alert validation**

```
SELECT * FROM logs;

```

### Part 2: Analysis - Scope

[//]: # (consolidate the list of all AWS resources affected)

*Collect the related activity recorded in CloudTrail, VPC Flow, and Route53 VPC DNS for analysis. This data should be saved in a secure location where incident response team members have the appropriate access to perform their role.*

**Queries used for scoping**

```
SELECT * FROM logs;

```

[//]: # (check source IP addresses against threat intelligence field)

**Determine reputation of IP addresses used with AWS API calls with the principal against a list containing details such as Cyber Threat Intelligence scores, and known/approved IP addresses used by the organization.** 


```
WHOIS 203.0.113.43
```

### Part 3: Analysis - Impact

[//]: # (analyze the information gathered throughout scoping)

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

### Part 4: Containment

[//]: # (prevent further damage to the environment and business processes)

### Part 5: Eradication

[//]: # (destroy all components configured by the actor)

### Part 6: Recovery 

[//]: # (restore configuration from backup and rebuild components as needed)

### Part 7: Post-Incident Activity

[//]: # (review all notes taken during the incident, submit for review proposed changes to enhance the security posture and incident response capabilities)


* * *
