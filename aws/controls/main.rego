package aws.controls

import rego.v1

evaluate_all(plan) := evaluate_ecs(plan)
