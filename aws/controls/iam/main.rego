package aws.controls.iam

import rego.v1

evaluate(plan) := union({evaluate_iam_1(plan)})
