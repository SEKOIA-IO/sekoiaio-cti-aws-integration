# Overview

This AWS Cloud Development Kit will allow you to automatically create Network Firewall rules with Sekoia.io's Threat Intel IoCs (domain names).

## What you will need

- A AWS S3 bucket
- A Sekoia.io account with an INTEL plan

## Installation

Install the Cloud Development kit <https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html>

If needed install the aws-cli <https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html>

Clone this repository
```
git clone https://github.com/SEKOIA-IO/sekoiaio-cti-aws-integration.git
```

Change directory
```
cd sekoiaio-cti-aws-integration/Sekoia-CTI-for-Network-Firewall
```

Create the virtual env and install dependencies
```
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt
```

Bootstrap
```
pip install -r requirements.txt
aws configure
cdk bootstrap
```

Deploy
```
cdk deploy --parameters APIKEYParameter=${APIKEY} --parameters BUCKETParameter=my-bucket
```

## What's next

At this point, we've created firewall rules for you. You'll need to update your firewall configuration to use them.


## Caveats

WIP 
- AWS 30K limitations

## Useful commands

- `cdk synth`       synthesize the CloudFormation template
- `cdk ls`          list all stacks in the app
- `cdk synth`       emits the synthesized CloudFormation template
- `cdk deploy`      deploy this stack to your default AWS account/region
- `cdk diff`        compare deployed stack with current state
- `cdk docs`        open CDK documentation
