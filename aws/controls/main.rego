package aws.controls

import data.aws.controls.ecs
import rego.v1

evaluate_all(plan) := union({ecs.evaluate(plan)})
