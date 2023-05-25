#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import aws_cdk
from workshop_stack import WorkshopStack

app = aws_cdk.App()

workshop_stack = WorkshopStack(app, "WorkshopStack")

app.synth()
