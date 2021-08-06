#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from aws_cdk import core
from core_stack import CoreStack
from simulation_stack import SimulationStack

app = core.App()

core_stack = CoreStack(app, "CoreStack")
simulation_stack = SimulationStack(app, "SimulationStack")

app.synth()
