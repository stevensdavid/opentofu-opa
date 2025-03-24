package aws.controls.lambda

import data.aws.utils as aws_utils
import data.utils

import rego.v1

evaluate_lambda_1(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_lambda_permission")
	public_access(configuration)

	violation := {
		"id": {"opa": "aws.controls.lambda.1", "control_tower": "CT.LAMBDA.PR.2"},
		"reason": "Require AWS Lambda function policies to prohibit public access",
		"resource": address,
		"severity": "critical",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolslambda1",
	}
}
