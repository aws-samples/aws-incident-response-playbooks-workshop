# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import setuptools

AWS_CDK_VERSION = "2.80"

with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="BuildingAWSIRPlaybooksWorkshop",
    version="1.0",

    description="Building playbooks for incident response in AWS workshop",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="AWS",

    package_dir={"": "."},
    packages=setuptools.find_packages(where="."),

    install_requires=[
        "aws-cdk-lib==" + AWS_CDK_VERSION,
    ],

    python_requires=">=3.10",

    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
)
