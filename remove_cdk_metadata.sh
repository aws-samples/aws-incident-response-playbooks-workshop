#!/bin/bash
# automatic removal of references to AWS CDK bootstrap using `yq`
yq -i 'del(.Rules)' cdk.out/WorkshopStack.yaml
yq -i 'del(.Conditions)' cdk.out/WorkshopStack.yaml
yq -i 'del(.Parameters.BootstrapVersion)' cdk.out/WorkshopStack.yaml
yq -i 'del(.Resources.CDKMetadata)' cdk.out/WorkshopStack.yaml
# end