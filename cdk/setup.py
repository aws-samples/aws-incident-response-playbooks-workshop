# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import setuptools

AWS_CDK_VERSION = "1.114.0"

with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="BuildingAWSIRPlaybooksWorkshop",
    version="0.0.3",

    description="Building playbooks for incident response in AWS workshop",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="AWS",

    package_dir={"": "cdk"},
    packages=setuptools.find_packages(where="cdk"),

    install_requires=[
        "aws-cdk.core==" + AWS_CDK_VERSION,
        "aws-cdk.aws-athena==" + AWS_CDK_VERSION,
        "aws-cdk.aws-s3==" + AWS_CDK_VERSION,
        "aws-cdk.aws-cloudtrail==" + AWS_CDK_VERSION,
        "aws-cdk.aws-glue==" + AWS_CDK_VERSION,
        "aws-cdk.aws-ec2==" + AWS_CDK_VERSION,
        "aws-cdk.aws-route53resolver==" + AWS_CDK_VERSION,
        "aws-cdk.aws-s3-assets==" + AWS_CDK_VERSION,
        "aws-cdk.aws-iam==" + AWS_CDK_VERSION,
        "aws-cdk.aws-lambda==" + AWS_CDK_VERSION,
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
