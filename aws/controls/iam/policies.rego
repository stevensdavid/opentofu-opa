package aws.controls.iam

import data.aws.utils as aws_utils
import data.utils

import rego.v1

evaluate_iam_1(plan) := {violation |
	some [statement, address] in all_iam_statements(plan)

	statement_allows_action(statement, "*")
	statement_allows_resource(statement, "*")

	violation := {
		"id": {"opa": "aws.controls.iam.1", "control_tower": "CT.IAM.PR.1"},
		"reason": "Require that an AWS Identity and Access Management (IAM) inline policy does not have a statement that includes \" * \" in the Action and Resource elements",
		"resource": address,
		"severity": "high",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolsiam1",
	}
}
