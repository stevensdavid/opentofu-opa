package aws.controls.lambda

import rego.v1

evaluate(plan) := union({evaluate_lambda_1(plan)})
