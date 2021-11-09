#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from aws_cdk import core
from workshop_stack import WorkshopStack

app = core.App()

workshop_stack = WorkshopStack(app, "WorkshopStack")

app.synth()
